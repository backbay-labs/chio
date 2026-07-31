# Chio Protocol

**Version:** 1.0
**Date:** 2026-04-14
**Status:** Current bounded Chio release profile

Chio is pre-release. This document describes the current v1 protocol profile.
Earlier internal draft versions have been folded into this v1 contract rather
than exposed as runtime compatibility layers.

---

## 1. Purpose

Chio is a capability-scoped mediation and evidence system for agent tool use.
In this repository it ships as:

- a native agent-to-kernel protocol for signed capability evaluation
- a kernel that emits signed receipts for allow, deny, cancelled, and
  incomplete outcomes
- trust-control services for authority, revocation, receipt, budget, and
  federation state
- MCP-compatible edges and adapters only where the kernel owns dispatch and
  receipt authority
- machine-readable official-stack, extension-manifest, negotiation, and
  qualification artifacts that remain subordinate to the v1 receipt contract
- machine-readable web3 trust, anchoring, oracle, and settlement artifacts that
  remain evidence artifacts unless a kernel-mediated dispatch path is present
- one bounded off-chain `chio-link` oracle runtime plus operator and
  qualification artifacts for conservative cross-currency budget enforcement
- one bounded `chio-anchor` runtime plus discovery, proof-bundle, and
  qualification artifacts for multi-lane checkpoint anchoring over that
  official web3 stack
- one bounded `chio-settle` runtime plus finality, Solana-preparation, and
  qualification artifacts for real settlement dispatch over that official web3
  stack
- one bounded Functions fallback, automation-job, CCIP settlement-
  coordination, and payment-interop surface over that official web3 stack
- one bounded web3 operations surface plus promotion-policy and partner-proof
  artifacts for operating and reviewing that official web3 stack honestly
- machine-readable autonomous pricing, capital-pool, execution, rollback, and
  qualification artifacts for one bounded insurance-automation lane
- machine-readable public identity-profile, wallet-directory, routing, and
  qualification artifacts for one bounded public identity network
- portable trust artifacts for `did:chio`, Chio-branded schema issuance,
  challenge/response presentation, evidence export, and certification

This document describes the protocol and artifact contract that the code in
this repository actually ships. It is intentionally narrower than the older
research draft that described aspirational networking and deployment topology.
When a later section names an adapter, bridge, external rail, hosted tool, or
directory surface, that section is normative only for the bounded artifact or
kernel-owned path it describes. It does not make trace-only provider activity,
remote hosted execution, or advisory directory data into an authoritative Chio
authorization receipt.

## 2. Scope And Compatibility

The shipped v1 contract covers:

- native capability and receipt validation
- wrapped MCP mediation only where Chio owns dispatch; hosted or remote
  provider-executed activity is trace-only unless a later implementation proves
  a live kernel-mediated dispatch boundary
- trust-control HTTP APIs for authority, receipts, revocation, budgets,
  federation, reputation comparison, and certification
- `did:chio`
- Agent Passport artifacts and verifier-policy distribution
- federated evidence export/import and cross-org delegation continuation
- A2A v1.0.0 consumption through `chio-a2a-adapter` only where receipt
  authority is backed by a live kernel authorization receipt
- signed certification checks plus operator-scoped registry and discovery-network
  surfaces
- one machine-readable extension inventory plus an official Chio stack package,
  custom extension manifest contract, fail-closed negotiation report, and
  extension qualification matrix; extension data cannot widen signed Chio truth
  or capability scope
- one machine-readable web3 trust profile, contract package, chain
  configuration, anchor-proof, oracle-evidence, dispatch, settlement-receipt,
  and qualification artifact family for the official web3 rail
- one bounded `chio-link` runtime profile, operator configuration, runtime
  report, receipt policy, and qualification artifact family for conservative
  cross-currency budget enforcement over that official web3 stack
- one bounded `chio-anchor` runtime profile, discovery artifact, imported
  OpenTimestamps and Solana memo secondary-lane contract, shared proof-bundle
  contract, and qualification artifact family over the official web3 stack
- one bounded `chio-settle` runtime profile, finality report, Solana release
  example, qualification artifact family, and runbook over the official web3
  stack
- one bounded Functions fallback profile plus request/response examples, one
  automation profile plus anchor/settlement job artifacts, one CCIP message
  profile plus reconciliation artifacts, and one payment-interop profile plus
  x402, EIP-3009, Circle, and ERC-4337 compatibility artifacts over the
  official web3 stack
- one bounded web3 operations profile plus anchor and settlement runtime
  reports, one deployment-promotion policy, and one reviewer-facing external
  qualification matrix over the official web3 stack
- one machine-readable autonomous pricing-input, authority-envelope,
  pricing-decision, capital-pool optimization, execution, rollback, drift,
  and qualification artifact family for the bounded automation lane
- one machine-readable public identity-profile, wallet-directory entry,
  wallet-routing manifest, and identity-interop qualification artifact family
  for the bounded public identity network
- one bounded Proof Room presentation surface (`chio proof serve`, section
  8.5) plus a machine-readable proof-room bundle, verifier-report,
  fixture-catalog, receipt-evidence, and first-run evidence artifact family;
  Proof Room artifacts render verified evidence and cannot widen signed Chio
  truth or capability scope

The shipped v1 contract does not claim:

- OpenAI hosted-tool mediation, OpenAI remote MCP execution, Bedrock Lambda
  mediation, voice execution, broad live-directory import, or any other adapter
  execution before receipt semantics, durable commit, semantic authority, and
  tenant read-boundary gates are merged and tested
- OAuth authorization-server product status before a dedicated accepted ADR or
  equivalent decision note defines scope, RAR grammar, telemetry, and
  feature-gating posture
- manifest event publish/consume actions before the current v1 manifest
  planning work is accepted and implemented
- multi-region consensus or Byzantine replication
- a public certification marketplace
- automatic SCIM provisioning lifecycle
- synthetic cross-issuer passport scoring
- theorem-prover completion for concrete crypto, platform, or external-service
  behavior beyond the published audited assumptions
- arbitrary plugins that can redefine signed Chio truth or widen trust outside
  named extension points
- permissionless public identity or wallet discovery that widens local trust
- generic OID4VP, SIOP, DIDComm, or permissionless wallet-network
  compatibility beyond Chio's documented public identity-profile and routing
  contract
- permissionless anchor discovery or arbitrary chain anchoring beyond Chio's
  documented EVM, OpenTimestamps, and Solana memo lanes
- arbitrary cross-chain fund routing, generic keeper authority, or direct fund
  release from Functions or paymaster infrastructure beyond Chio's documented
  bounded web3 interop surfaces
- a replacement of MCP or A2A at the wire-protocol ecosystem level

### HTTP And OpenAPI Surfaces

The v1 contract also covers:

- an HTTP substrate sidecar protocol for protecting arbitrary HTTP APIs through
  Chio policy evaluation, typed HTTP receipts, and structured verdicts (see
  [HTTP-SUBSTRATE.md](HTTP-SUBSTRATE.md))
- an OpenAPI-to-manifest pipeline that derives `chio.manifest.v1` tool
  definitions from OpenAPI specifications with `x-chio-*` policy extensions (see
  [OPENAPI-INTEGRATION.md](OPENAPI-INTEGRATION.md))
- a reverse-proxy entrypoint (`chio api protect`) that combines OpenAPI
  ingestion, sidecar evaluation, and live traffic enforcement
- certificate management CLI surfaces (`chio cert generate`, `chio cert verify`,
  `chio cert inspect`) for operator-facing TLS and signing material

These surfaces share the same core receipt, capability, and policy primitives
documented below. The HTTP substrate's `HttpReceipt` maps
deterministically to `ChioReceipt` so all existing receipt verification,
checkpoint, and evidence-export workflows continue to apply.

Compatibility rule:

- additive fields may appear in JSON responses and signed artifacts
- unknown schema identifiers for schema-tagged artifacts must be rejected
- fail-closed behavior is part of the protocol contract, not an implementation
  detail

## 3. Components And Trust Boundaries

Chio in this repository uses these roles:

| Component | Role |
| --- | --- |
| Agent | Untrusted caller that presents a capability or authenticates to a hosted edge |
| Kernel | Trusted enforcement layer that validates capabilities, runs guards, dispatches calls, and signs receipts |
| Tool server | Native or wrapped implementation of tools/resources/prompts |
| Trust-control | Operator-facing authority, receipt, revocation, budget, federation, and certification service |
| Hosted MCP edge | `chio mcp serve-http`, which exposes an MCP-compatible HTTP surface with remote session lifecycle and admin APIs |
| Operator stores | SQLite stores and file-backed registries for authoritative local state |

The security boundary that matters is constant across these surfaces:

- the agent never receives ambient authority
- every mediated action is bound to explicit capability or authenticated hosted
  session state
- denials are explicit, signed, and auditable
- extensions may replace only named seams and must still preserve local policy
  activation plus signed Chio truth
- registry and artifact mismatches fail closed instead of degrading silently

## 4. Serialization And Identity

### 4.1 Canonical JSON

Signed Chio artifacts use canonical JSON serialization before signing. Classical
artifacts remain Ed25519 by default. Post-quantum hybrid artifacts use the
`hybrid:<classical>:<pq>:<alg_set>` string prefix, where `pq` is ML-DSA-65
bytes encoded as lowercase hex and `alg_set` is one of
`ed25519+mldsa65`, `p256+mldsa65`, or `p384+mldsa65`. Verifiers dispatch from
the self-describing signature prefix and reject malformed or mismatched hybrid
halves fail-closed.

This includes capability tokens, receipts, manifests, checkpoints, verifier
policies, passport presentations, and certification artifacts.

### 4.2 Native Wire Format

The native agent-to-kernel protocol uses length-prefixed JSON messages with a
`type` discriminator. The core messages are defined by `AgentMessage` and
`KernelMessage` in `crates/core/chio-core/src/message.rs`.

The normative wire definition for this shipped surface now lives in
[WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).

Request examples:

- `tool_call_request`
- `list_capabilities`
- `heartbeat`

Response examples:

- `tool_call_chunk`
- `tool_call_response`
- `capability_list`
- `capability_revoked`
- `heartbeat`

### 4.3 Hosted Wire Format

The hosted edge uses MCP-compatible HTTP semantics rather than the native
length-prefixed transport:

- JSON-RPC over HTTP POST
- standalone GET/SSE streams where supported by the hosted edge
- bearer-token or JWT-backed session admission
- remote admin APIs under `/admin/...`

Hosted initialization, session replay, and lifecycle expectations are defined
normatively in [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md).
The shipped hosted contract is now fixed enough that guides and examples should
describe it literally:

- `initialize` is a `POST /mcp` request, not a GET bootstrap.
- successful initialize returns an SSE response plus `MCP-Session-Id`.
- clients send `notifications/initialized` before relying on ready-state
  methods such as `tools/list` or `tools/call`.
- `GET /mcp` is the live-and-replay notification stream, with `Last-Event-ID`
  as the replay cursor.
- shared-owner hosted deployments may reuse one upstream subprocess, but task
  handles and late notifications remain scoped to the originating session.
- caller-supplied model metadata is preserved on the request path, but its
  provenance enters Chio as `asserted` until a trusted subsystem upgrades it.

### 4.4 Identity

Chio uses Ed25519 keys as the primary cryptographic identity primitive.
Hybrid public keys are encoded with the same self-describing prefix discipline
as signatures: `hybrid:<classical-public-key>:<mldsa65-public-key>:<alg_set>`.
Classical encodings remain byte-identical.

`did:chio` remains the shipped self-certifying DID method for those keys in
this release:

```text
did:chio:{64-hex-ed25519-public-key}
```

Resolution is local and self-certifying. Optional service endpoints, such as a
receipt-log URL, may be attached by the resolving environment.

Broader public identity profiles may also name `did:web`, `did:key`, and
`did:jwk` as compatibility inputs for wallet or issuer interoperability, but
those methods do not replace `did:chio` as Chio's canonical provenance anchor in
this release.

## 5. Capability Contract

The shipped capability token is `CapabilityToken` from
`crates/core/chio-core-types`.

Capability tokens are schema-tagged signed artifacts. Newly issued tokens carry
`schema: "chio.capability.v1"` in the schema-aware signing input. Load-time and
verify-time paths reject any unknown capability schema.

The v1 signed body is:

| Field | Meaning |
| --- | --- |
| `id` | Stable capability identifier used for revocation |
| `issuer` | Algorithm-aware public key of the authority or delegating issuer |
| `subject` | Algorithm-aware public key bound to the caller |
| `scope` | Tool, resource, and prompt grants |
| `issued_at` | Unix timestamp seconds |
| `expires_at` | Unix timestamp seconds |
| `delegation_chain` | Ordered chain of delegation links |
| `aggregate_invocation_budget` | Optional capability-wide or delegation-family invocation ceiling |
| `algorithm` | Optional envelope hint: `ed25519`, `p256`, `p384`, or `hybrid` |

Capability public-key fields and signatures use the same self-describing
encoding defined in section 4. Hybrid capability tokens set
`algorithm: "hybrid"` and encode `issuer`, `subject`, delegation-link keys,
and signatures as `hybrid:<classical>:<mldsa65-hex>:<alg_set>`. Verifiers
MUST dispatch from the signature prefix, confirm any present `algorithm` hint
matches that prefix, and reject mismatches fail-closed. The algorithm enum
MUST NOT contain concrete algorithm-set strings such as `ed25519+mldsa65`;
those strings live only inside the hybrid wire value.

### Capability Negotiation

Federated peers exchange `chio.capabilities.v1` during trust establishment.
The envelope carries a string-keyed feature bitset. Peers proceed only with the
intersection of features both sides advertise. Malformed feature names and
unsupported schema IDs fail closed before a peer can use a negotiated feature.

Initial feature names are:

- `accepts_anchor_batch_v1`
- `accepts_hybrid_signatures`
- `delegation_chain_binding`

Peers that do not advertise the bitset stay on the v1 default. Capability schema
selection is not negotiated before public release: `chio.capability.v1` is the
only Chio-owned token schema accepted by runtime verifiers.

### Signed-Artifact Registry

`spec/schemas/registry.json` is the signed-artifact compatibility registry.
Every signed artifact schema ID that a verifier accepts must be listed there.
Verifier builds also expose the same IDs through
`KNOWN_SIGNED_ARTIFACT_SCHEMAS`. Unknown signed-artifact schemas are rejected at
load time and again at signature verification time.

The FROST quorum substrate registers four signed artifact schemas:

- `chio.frost.roster.v1`
- `chio.frost.epoch-checkpoint.v1`
- `chio.frost.authorization-slot-checkpoint.v1`
- `chio.frost.authorization.v1`

The parametric-insurance contract registers one signed artifact schema:

- `chio.parametric.policy.v1`

Its registry kind is `parametric_policy`, introduced by
`parametric-insurance-v1`, with the envelope schema at
`spec/schemas/chio-parametric/v1/policy.schema.json`. Trigger-instance keys and
evidence-corpus manifests are canonical policy inputs, not signed-artifact
schemas.

The credit-admission contract registers one signed artifact schema:

- `chio.credit.facility-bind.v1`

Its registry kind is `credit_facility_bind`, introduced by
`credit-admission-v1`, with the envelope schema at
`spec/schemas/chio-economy/credit-facility-bind.v1.json`. The configured
facility authority, debtor, and original creditor sign the same canonical body.
That body binds the admission operation and request, economic intent, facility
artifact and authority set, exposure version and fence, parties and payee,
tool scope, amount and effective ceiling, due date, nonce, and validity window.
An admission verifier MUST reject every unknown facility-bind version before
signature verification and MUST NOT mint credit without the matching online
authoritative exposure reservation.

The receivables-factoring contract registers six signed artifact schemas:

- `chio.obligation.status-proof.v1`
- `chio.credit.receivable-iou-envelope.v1`
- `chio.factor.assignment-bind-authorization.v1`
- `chio.factor.assignment-agreement.v1`
- `chio.factor.assignment-acknowledgement.v1`
- `chio.factor.assignment-not-applied.v1`

Their registry kinds are `obligation_status_proof`, `credit_iou_envelope`,
`factor_assignment_bind_authorization`, `factor_assignment_agreement`,
`factor_assignment_acknowledgement`, and `factor_assignment_not_applied`, all
introduced by `receivables-factoring-v1`. Their envelope schemas are published
under `spec/schemas/chio-economy/`.

The v2 IOU envelope embeds the exact signed facility bind. Its
`creditAuthorityDigest` MUST equal the SHA-256 digest of the canonical embedded
bind and MUST match the credit authority digest in the source receipt and
obligation atom. A receipt, audit log, anchor, or partition lease does not
replace the facility signatures or the authoritative exposure compare-and-swap.

The following factoring schemas are unsigned canonical projections:

- `chio.factor.normalized-assignment-request.v1`
- `chio.factor.receivable-claim.v1`
- `chio.factor.assignment-offer.v1`
- `chio.factor.discount-quote.v1`

They become evidence only through an exact digest bound by the signed artifacts
above. They are not independently authenticated and MUST NOT be accepted as a
substitute for the status proof, IOU envelope, bilateral agreement, bind
authorization, or terminal result.

The six signed schema IDs above are exhaustive for this contract version. A
receivables verifier MUST reject every unknown schema version before signature
verification, including an older IOU envelope or a future factoring version,
and MUST NOT downgrade, reinterpret, or fall back to a known version.

Verified-outcome pricing registers nine independently signed artifact schemas:

- `chio.outcome.predicate.v1`
- `chio.outcome.pricing.v1`
- `chio.outcome.sla.v1`
- `chio.outcome.eligibility.v1`
- `chio.outcome.delivery-checkpoint.v1`
- `chio.outcome.delivery-acknowledgement.v1`
- `chio.outcome.delivery-nonacceptance.v1`
- `chio.outcome.output-provenance.v1`
- `chio.outcome.contractual-zero.v1`

Their registry kinds use the `outcome_` prefix and are introduced by
`verified-outcome-pricing-v1`. Their envelope schemas are published under
`spec/schemas/chio-outcome/v1/`. `chio.outcome.request.v1` and
`chio.outcome.verdict.v1` are unsigned projections and are not signed-artifact
schemas.

Roster, epoch-checkpoint, and authorization-slot signatures MUST verify against
separately configured Ed25519 trust roots for their exact authority role and
key id. Those artifacts carry key ids, never authority public keys. A verifier
MUST reject an embedded-key field, an unknown key id, a key trusted for another
role, or a signature that does not verify over the artifact's domain-separated
RFC 8785 preimage. The corresponding prefixes are
`CHIO-FROST-ROSTER-V1\0`, `CHIO-FROST-EPOCH-CHECKPOINT-V1\0`, and
`CHIO-FROST-AUTHORIZATION-SLOT-CHECKPOINT-V1\0`.

Checkpoint digests commit the signed checkpoint, including its authority
signature. Sequence one has no predecessor; every later sequence names the
previous checkpoint digest. An active authorization verifier MUST reread and
authenticate the rollback-independent epoch checkpoint immediately before
execution, even when it already holds a previously verified roster. It MUST
also authenticate the exact permanently completed authorization-slot
checkpoint and compare its canonical authorization blob byte-for-byte. Schema
validity alone is never signature or trust-root validity.

### 5.1 Scope

The shipped scope model includes:

- `grants: Vec<ToolGrant>`
- `resource_grants: Vec<ResourceGrant>`
- `prompt_grants: Vec<PromptGrant>`

`ToolGrant` includes:

- `server_id`
- `tool_name`
- `operations`
- `constraints`
- `max_invocations`
- `max_cost_per_invocation`
- `max_total_cost`
- optional `dpop_required`

The shipped `constraints` surface includes ordinary argument constraints plus
governed-transaction controls such as `governed_intent_required`,
`require_approval_above`, and `seller_exact`, and three delivery controls:
`output_digest_sha256` (the expected post-transform output digest, enforced
at the output-aware durable terminal), `require_finding_purchase` (a
provider-signed purchase marker binding `finding_id`, `listing_id`, and a
closed settlement selector whose modes are `local_reversible_hold` and
`cross_org_escrow` with a pinned `settlement_profile_sha256`), and
`require_finding_recovery` (a no-charge recovery marker binding the original
capability, settled purchase, successful delivery receipt, and one durable
attempt ceiling shared by every deterministic re-mint). Recovery capabilities
are undelegated, DPoP-bound, single-grant authorities with exactly one output
digest and no monetary ceiling. Surfaces without the corresponding
output-aware, purchase-aware, or recovery-aware admission reject these
delivery controls fail-closed before any budget or payment mutation. Their
`Custom`-keyed spellings, including the retired receipt- and
capability-keyed recovery aliases, are rejected as downgrade attempts.

### Capability Attenuation

`chio.capability.v1` includes delegation and attenuation in the signed token
body:

- typed first-party `caveats` with `{ kind, predicate, sig? }`
- `scope_attenuations` carrying the narrowing operations
- `attenuation_proof` with `parentScopeHash`, `childScopeHash`, and a
  `normalizedSubsetProof`
- optional `budget_share_bps`, a fixed-point child budget share capped at 10000

The witness API is:

```rust
compute_attenuation_witness(parent: &ChioScope, child: &ChioScope)
verify_attenuation_witness(parent_hash, child_hash, witness)
```

Minting and verification both check that the child scope hash in the proof
matches the token scope, that the witness hashes match the normalized scopes,
and that every recorded grant relation is a subset. Budget shares above 10000
bps fail closed because they re-amplify parent authority.

#### Chain-Binding Rule (W1.1)

The `attenuation_proof.parent_scope_hash` field MUST be bound to the token's
upstream lineage. Without this rule an issuer with true authority `scope_X`
could mint a token claiming `parent_scope = scope_BIGGER` and supply an
internally consistent witness, because nothing tied `parent_scope_hash` to
the issuer's actual upstream parent capability. Concretely:

- Every delegation hop carries a signed `DelegationLink.scope_hash` that
  records the canonical hash of the scope authorized at that step.
- A direct-issue token (empty `delegation_chain`) MUST have
  `attenuation_proof.parent_scope_hash` equal to the verifier's
  trust-root scope hash for the issuing authority.
- A delegated token MUST have `attenuation_proof.parent_scope_hash`
  equal to `delegation_chain.last().scope_hash`. The chain-link signature
  binds that hash to the predecessor's key, transitively rooting the
  witness in the trust-root authority.
- A chain whose hops omit `scope_hash` is rejected fail-closed.

The portable verifier entrypoint
`chio_kernel_core::verify_capability_with_floor_and_trust_root(token,
trusted_issuers, clock, crypto_floor, trust_root_scope_hash)` enforces
the rule in isolation. Production kernels MUST route every inbound
capability admission through the composite entrypoint
`chio_kernel_core::verify_capability_full(token, trusted_issuers,
clock, crypto_floor, peer, trust_root, budgets)`, which chains the W1.1
chain-binding check and the W1.2
sibling-sum budget admission alongside signature, floor, and time-bound
verification. The earlier partial entry points
(`verify_capability_with_floor`,
`verify_capability_with_negotiated_floor`,
`verify_capability_with_floor_and_trust_root`,
`verify_capability_with_floor_and_resolver`) remain available for
isolated unit tests and bounded research adapters; they MUST NOT be
the sole verifier on a production hot path because each one leaves
at least one required defense un-wired and the resulting bypass is
silent. Kernel implementations MAY split the call into two phases --
a pre-admit pass with `NoopBudgetRegistry` followed by an authoritative
admit against the persistent registry once every other check has
passed -- but every reachable kernel surface (hosted tool dispatch,
plan-step pre-flight, session/resource/prompt operations, federated
nested-flow bridges) MUST traverse `verify_capability_full` exactly
once per admission decision.

The two-phase split is intentionally asymmetric. The pre-admit
verifier pass (signature + crypto-floor + W1.1 chain-binding + time-window)
MUST run on every surface listed above.
The authoritative budget admit phase (W1.2 sibling-sum) MUST run on
hosted tool dispatch and federated nested-flow bridges -- the surfaces
that actually execute a side-effecting action against the budget --
and MAY be omitted on plan-step pre-flight (which is a verdict-only
preview that does not dispatch the underlying tools) and on
session/resource/prompt operations (which are read-only metadata
exchanges that do not consume the caller's invocation budget). Kernel
implementations that omit the admit phase on these stateless surfaces
MUST document the omission alongside the surface helper. The
The W1.1 chain-binding fixture asserts the pre-admit pass MUST; the W1.2
sibling-sum admit MUST is asserted by the hosted-dispatch admit fixtures (e.g.
`budget_split_cross_hop_rejects_amplification.rs`,
`hot_path_enforcement.rs`). Both rejection paths surface
`CapabilityError::AttenuationViolation` with the offending hashes
formatted as hex. The check costs a single hash comparison on the
happy path and runs after the basic signature, time, and crypto-floor
checks (the chain binding is meaningful only once those succeed).

The MUST above is enforced by conformance fixtures that construct an attenuated
capability whose `attenuation_proof.parent_scope_hash` does not bind to any
registered trust root and assert that production dispatch surfaces deny. If a
future refactor reintroduces a kernel-side verifier shortcut that bypasses
`verify_capability_full`, those fixtures must fail.

Worked example. An issuer with trust-root authority hash `H_root` mints
a capability directly (empty `delegation_chain`). The verifier accepts
the token only if `attenuation_proof.parent_scope_hash == H_root`. If
the issuer further delegates to Bob, the resulting hop's
`DelegationLink.scope_hash` is `H_bob`, and Bob's downstream token
must carry `attenuation_proof.parent_scope_hash == H_bob`. A token that
claims `parent_scope_hash == H_BIGGER` (any unbound hash) is rejected
with `CapabilityError::AttenuationViolation`.

The Lean theorem `theorem.attenuation.witness_soundness` in
`formal/lean4/Chio/Chio/Proofs/AttenuationWitness.lean` models the
chain-binding check, and the Rust shell is exercised by
`crates/tooling/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs`.

#### Sibling-Sum Budget Enforcement (W1.2)

The `<= 10000 bps` per-token cap is necessary but not sufficient: a parent
at `5000 bps` could mint two children at `4000 bps` each, and per-token
validation would happily accept both, letting the children jointly claim
80% of the parent's authority while the parent itself only owns 50%. The
W1.2 fix closes that gap with a registry hook at the verifier:

- The portable verifier maintains a per-parent `BudgetRegistry` (in-process
  by default, via `chio_kernel_core::InMemoryBudgetRegistry`).
- When the verifier admits a freshly delegated child token, it asks the
  registry whether the parent has enough remaining headroom. If the
  running sum of admitted sibling shares plus the new child's share
  would exceed the parent's share, the registry rejects the child and
  verification fails closed with
  `CapabilityError::BudgetSplitRejected(BudgetSplitError::OversubscribedSiblings)`.
- The check composes across hops: a grandchild's admission is checked
  against its immediate parent's admitted share, not just the root, so
  cross-hop amplification (parent 5000, child 4000, two grandchildren
  3000 each) is rejected fail-closed at the second grandchild.
- Idempotency: re-admitting the same child id with the same share is a
  silent success; a different share for the same id is a hard failure
  because it would let an attacker rewrite the split after the fact.
- Overflow safety: the running sum is computed in `u32` so two
  `u16::MAX` siblings cannot wrap around the cap.

The kernel-side entry point is
`chio_kernel_core::evaluate_with_crypto_floor_and_budgets(input,
crypto_floor, &mut dyn BudgetRegistry)`. Hosted callers
(`chio-kernel`) instantiate a process-scoped `InMemoryBudgetRegistry`
and pass it through; portable callers can supply their own
`BudgetRegistry` implementation against external storage. The Lean
theorem `theorem.budget.sibling_sum_soundness` in
`formal/lean4/Chio/Chio/Proofs/SiblingSumBudget.lean` models the
admit check, and the Rust shell is exercised by
`crates/tooling/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs`
and `crates/tooling/chio-conformance/tests/budget_split_cross_hop_rejects_amplification.rs`.

#### Aggregate Invocation Budgets And Threshold Approval

An `aggregate_invocation_budget` bounds invocations across every grant in one
capability or across every descendant in one delegation family. Capability
scope uses the capability ID as the quota owner. Delegation-family scope uses
the owner derived from a verified, CA-signed `chio.aggregate-budget-root.v1`
binding. A family descendant MUST carry the identical root binding and signed
maximum from its direct root. It MUST NOT lower, raise, omit, replace, or create
that family budget. A maximum of zero is valid and denies every capture.

The verifier MUST authenticate the direct root token and bind the root
capability ID, root commitment hash, issuer, subject, scope hash, expiry,
maximum, root-binding signature, and descendant binding digest. Presented
delegation metadata is not authority for a family owner. An untrusted root,
forged field, changed digest, or missing direct-root token is a denial.

When a request is covered by grant, aggregate, or supplemental invocation
quotas, the durable authority authorizes and captures the complete sorted quota
set atomically. Exhaustion or an immutable-maximum mismatch on any member
leaves every member unchanged. Supplemental authorization is opaque caller
input until an installed verifier returns a bound claim. The verifier binds the
claim to the subject, request, destination, validity window, and authority
state; callers cannot construct a quota claim directly.

A governed operation that requires threshold approval uses a signed
`chio.threshold-approval-proposal.v1` from the active policy authority. The
proposal fixes the request, governed intent, subject, authorizing capability,
policy hash, distinct eligible-key set digest, exact threshold, creation time,
and deadline. Approval tokens count only once per distinct eligible public key
and MUST fall inside the proposal window. The complete verified set sorts
distinct token digests before applying the `chio.verified-approval-set.v1`
domain-separated hash. Token order therefore cannot change the set hash or the
decision.

Unsupported negotiation denies these features instead of downgrading them.
Portable binding vectors are maintained in
`crates/core/chio-adversarial-suite/cases/authority_binding_mutation/` and are
executed by
`crates/tooling/chio-conformance/tests/protocol_primitives_authority_bindings.rs`.
Durable quota, saga, broker, restart, HA, and receipt/store parity cases remain
in the kernel integration suites so they exercise the production authority and
not a parallel conformance model.

### 5.2 Governed Transaction Extensions

Tool-call requests may attach two optional governed artifacts:

- `governed_intent`, a canonical request intent carrying `id`, `server_id`,
  `tool_name`, `purpose`, optional `max_amount`, optional seller-scoped
  `commerce { seller, shared_payment_token_id }`, optional
  `metered_billing { settlement_mode, quote, max_billed_units }`, optional
  asserted `call_chain { chain_id, parent_request_id, parent_receipt_id?,
  origin_subject, delegator_subject }`, and optional structured context
- `approval_token`, a signed approval artifact bound to one subject, one
  request id, and one governed intent hash

The `metered_billing.quote` sub-block is the payment-rail-neutral pre-execution
estimate for non-rail tools. It carries:

- `quote_id`
- `provider`
- `billing_unit`
- `quoted_units`
- `quoted_cost { units, currency }`
- `issued_at`
- optional `expires_at`

`metered_billing.settlement_mode` expresses whether the governed action is
expected to use `must_prepay`, `hold_capture`, or `allow_then_settle` semantics.
This is evidence and operator context, not the hard enforcement boundary by
itself. The kernel still enforces issued budgets and explicit governed limits.

When a matched grant includes `governed_intent_required`, the kernel requires
`governed_intent`. When a matched grant includes
`require_approval_above { threshold_units }`, the kernel requires a valid
`approval_token` whenever the provisional charged amount meets or exceeds that
threshold. When a matched grant includes `seller_exact`, the kernel requires
seller-scoped commerce approval context and denies if the governed seller does
not match the grant seller scope.

Approval tokens are verified against trusted authority keys and are bound to:

- the request `request_id`
- the capability `subject`
- the canonical hash of the attached governed intent
- approval-token `issued_at` and `expires_at` time bounds

Chio's normative provenance model now distinguishes three evidence classes:

- `asserted`: caller-supplied context that Chio preserves but has not
  independently authenticated
- `observed`: local lineage facts Chio directly observed inside one authenticated
  session
- `verified`: lineage Chio checked against signed artifacts such as
  `chio.session_anchor.v1`, `chio.receipt_lineage_statement.v1`, or
  `chio.call_chain_continuation.v1`

The provenance substrate uses these versioned artifacts:

- `chio.session_anchor.v1`: signed anchor binding `session_id`, `agent_id`,
  transport/auth context, proof-binding material, and auth epoch
- `chio.request_lineage_record.v1`: persisted request node keyed by
  `request_id`, carrying session-anchor and capability lineage joins
- `chio.receipt_lineage_statement.v1`: signed parent/child receipt edge
- `chio.call_chain_continuation.v1`: signed cross-kernel continuation token

The current bounded release emits session anchors and request-lineage records
for local continuity and nested-flow provenance. Receipt-lineage statements and
continuation tokens are the stronger receipt-to-receipt and cross-kernel proof
forms when present; their absence must not be silently treated as verified
upstream truth.

Compatibility `governed_intent.context.callChainUpstreamProof` remains a compatibility
input during migration, but the stronger continuation artifact for new work is
`governed_intent.context.callChainContinuation`.

If `governed_intent.call_chain` is present, the kernel rejects empty fields and
self-referential `parent_request_id == request_id` bindings. That input is
always `asserted` provenance at admission time. Chio may only upgrade it to
`observed` or `verified` when the runtime binds it to local request lineage,
a signed receipt-lineage statement, or a verified continuation token scoped by
the relevant session anchor. Reports and exports must preserve that evidence
class boundary instead of silently upgrading caller input into proof.

### 5.3 Verification Rules

The kernel and trust surfaces verify, at minimum:

1. Ed25519 signature validity
2. current time is within `issued_at <= now < expires_at`
3. the requested target is contained by the grant set
4. the presented capability and any preserved delegation structure are
   syntactically valid for the bounded shipped profile
5. revocation state is clear for the presented capability and any presented
   delegation ancestor IDs
6. DPoP proof is valid when the selected grant requires it
7. policy guards pass

Any failure denies or rejects the action instead of widening access.

### 5.4 Safety Properties And Evidence Boundary

The current launch-candidate safety inventory is:

- `P1` capability attenuation: supported delegated capability issuance can only
  narrow scope relative to the issuing parent
- `P2` presented revocation coverage: a revoked capability or revoked
  presented delegation ancestor ID is denied
- `P3` fail-closed evaluation: verification or policy failures deny or reject
  rather than widening access
- `P4` receipt integrity: signed receipts and checkpoints remain verifiable as
  evidence artifacts
- `P5` presented delegation-chain structural validity: delegation depth,
  connectivity, and timestamp monotonicity helpers define the bounded
  structural contract for a presented chain
- `P6` local parent-link soundness: an `observed` local parent edge implies
  the parent request existed in the same authenticated session when the child
  request was created
- `P7` receipt-lineage soundness: a `verified` receipt edge implies both
  receipts verify and the linkage was signed by a trusted kernel
- `P8` session continuity soundness: continued provenance can only claim
  session continuity through a valid session anchor and continuation artifact
- `P9` delegation/provenance consistency: verified call-chain subjects and
  parent capability references remain consistent with capability lineage
- `P10` report truthfulness: enterprise/report/export surfaces never label
  `asserted` lineage as `verified`

Chio intentionally distinguishes evidence classes for these claims:

- root-imported Lean proofs in `formal/lean4` cover the bounded P1-P10
  protocol models named by `formal/theorem-inventory.json`
- `formal/assumptions.toml` names the audited external primitives and platform
  services that are trusted rather than proved from first principles
- executable differential tests in `formal/diff-tests` are the Rust/spec drift
  gate for scope-attenuation semantics
- `scripts/check-aeneas-production.sh` extracts the production-linked pure
  core in `chio-kernel-core` through Charon/Aeneas into Lean, and
  `scripts/check-aeneas-equivalence.sh` hard-gates tracked Lean equivalence
  for that extracted lane; the older pilot lane remains as compatibility
  evidence
- Creusot/Kani strict lanes are declared in `formal/rust-verification` for
  production implementation linkage, including public Kani harnesses for
  `verify_capability`, `NormalizedScope::is_subset_of`,
  `resolve_matching_grants`, `evaluate`, and `sign_receipt`
- `scripts/check-adapter-no-bypass.sh` checks adapter mediation markers so
  MCP, API protect, and OpenAPI sidecar flows cannot drift away from kernel
  evaluation and receipt production unnoticed
- `scripts/generate-proof-report.sh` emits `target/formal/proof-report.json`
  from the manifest, theorem inventory, assumptions, claim gate inputs, tool
  versions, theorem source locations, artifact hashes, git state, and
  optional live gate results
- conformance and release-qualification lanes verify mediated protocol
  behavior, packaging, and clustered operator workflows

Chio's formal claim is implementation-linked and assumption-bounded: the
security-critical protocol semantics are mechanically checked in Lean and tied
to the pure Rust decision core, while concrete crypto, clock, storage,
transport, subprocess, hosted-registry, and chain behavior remains inside the
published audited assumptions.

### 5.5 Verified Core Boundary

The current implementation-linked verified-core contract is defined in
`formal/proof-manifest.toml`, with external-system assumptions in
`formal/assumptions.toml` and theorem coverage in
`formal/theorem-inventory.json`.

That manifest names the Rust symbols inside the present proof-facing boundary:

- `chio_kernel_core::capability_verify::{verify_capability, verify_capability_with_trusted}`
- `chio_kernel_core::scope::{resolve_matching_grants, resolve_capability_grants}`
- `chio_kernel_core::evaluate::evaluate`
- `chio_kernel_core::receipts::sign_receipt`

It also names the two shell entrypoints that may claim direct use of that pure
core today:

- `chio_kernel::ChioKernel::evaluate_portable_verdict`
- `chio_kernel::ChioKernel::build_and_sign_receipt`

Anything outside that manifest is outside the current proof boundary. Concrete
cryptography, clocks, storage, transport, subprocess behavior, hosted
registries, clustering, and external settlement rails are assumption-bound
unless and until they receive their own manifest entry and proof lane.

## 6. Receipt Contract

The current pre-release v1 receipt envelope is `ChioReceipt` from
`crates/core/chio-core-types/src/receipt.rs`.

| Field | Meaning |
| --- | --- |
| `id` | Authoritative content-addressed receipt identifier |
| `timestamp` | Unix timestamp seconds |
| `capability_id` | Capability exercised or presented |
| `tool_server` | Target server id |
| `tool_name` | Target tool |
| `action` | Canonicalized tool parameters plus `parameter_hash` |
| `receipt_kind` | `mediated_decision`, `trace_observation`, or `advisory_evaluation` |
| `boundary_class` | Runtime boundary: `prevent`, `detect_only`, or `advisory_only` |
| `observation_outcome` | Trace/advisory outcome. Omitted for mediated decisions |
| `tool_origin` | Where the tool effect executed relative to Chio |
| `redaction_mode` | Signed redaction mode for receipt details |
| `actor_chain` | Signed actor attribution chain |
| `decision` | Present only for `mediated_decision` + `prevent` receipts |
| `content_hash` | Hash of the evaluated content or outcome payload |
| `policy_hash` | Hash of the policy material used |
| `evidence` | Per-guard evidence |
| `metadata` | Optional structured metadata |
| `trust_level` | `mediated`, `verified`, or `advisory`, coherent with `receipt_kind` |
| `tenant_id` | Optional authenticated tenant id |
| `bbs_projection_version` | Optional BBS projection selector. Present only when `bbs_signature` is present, included in the receipt id, and fixed to `chio.bbs-projection.receipt.v1` for v1 receipt BBS material |
| `kernel_key` | Verifying public key; bare 64-hex Ed25519, `p256:<130-hex>` SEC1 P-256, or `p384:<194-hex>` SEC1 P-384 |
| `bbs_signature` | Optional BBS signature material for selective disclosure. When present, it is covered by the authoritative receipt signature |
| `algorithm` | Optional envelope hint (`ed25519`, `p256`, or `p384`); verification dispatches off the signature prefix, not this field |
| `signature` | Algorithm-aware hex signature over canonical JSON of `ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature? }`. The schema regex is `^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$`: bare 128-hex for Ed25519, `p256:<DER hex>` for P-256, or `p384:<DER hex>` for P-384 |

### WYSIWYS Signing Invariant

Receipt signing is WYSIWYS (what you see is what you sign). The production
signing primitive (`chio_kernel_core::receipts::sign_receipt`) takes the
canonical content preimage alongside the receipt body: the RFC 8785 canonical
JSON for a value output, the concatenated per-chunk digest preimage for a
stream receipt, or the literal `null` canonicalization for an empty output.
The signer recomputes `content_hash` from that preimage inside its own trust
boundary and MUST NOT trust the caller's asserted `content_hash`. When the
recomputed hash disagrees with the body's claimed `content_hash`, signing
MUST fail closed (`ContentHashMismatch`); the recompute runs before the
kernel-key check and before any signing work, so a mismatched body can never
reach the signer. This closes the render-A / sign-B forgery: a caller cannot
render content `A` while submitting a body that claims the hash of content
`B`.

One explicit exception exists. `sign_receipt_relaying_trusted_body` is the
auditable trusted-relay seam for thin FFI and WASM transport adapters (mobile
FFI, browser WASM, C++ FFI) that receive an already-minted, serialized
receipt body across their boundary and therefore do not hold the content
preimage. That entrypoint trusts the caller-supplied `content_hash` while
still enforcing the kernel-key match. It MUST NOT be used on any path that
holds the evaluated content; every such path MUST call `sign_receipt` (or the
one-time-handle variant that delegates to it) so the recompute-and-refuse
check applies. Threading the preimage across the FFI/WASM boundary so those
adapters can recompute too is tracked as follow-up work; until
then, this seam is the single place where caller-asserted `content_hash` is
trusted, rather than that trust being a silent default.

### Receipt Identity And DAG

`chio.receipt.v1` is content-addressed. The authoritative receipt identity is
`id`.

The receipt-id input contains every receipt body field except `id`. It includes
`bbs_projection_version` when present, but excludes `bbs_signature` bytes. The
receipt id is:

```text
id = H(canonical_jcs(ChioReceiptIdInput))
```

The signature input is the typed wrapper:

```text
ChioReceiptSigningBody { id, body: ChioReceiptIdInput }
```

When BBS receipt material is present, the signature wrapper also carries
`bbs_signature`:

```text
ChioReceiptSigningBody { id, body: ChioReceiptIdInput, bbs_signature }
```

Before the id is computed, the producer binds a signing nonce into the
receipt body. The nonce is the pre-binding receipt `id` (the producer's
content-addressed id for the body as first assembled), recorded under the
reserved `metadata` key `chio_receipt_signing_nonce`:

```text
metadata["chio_receipt_signing_nonce"] = pre_nonce_id
```

The binding happens once, in order: validate the body, write
`chio_receipt_signing_nonce` into `metadata`, then compute `id =
H(canonical_jcs(ChioReceiptIdInput))` over the now-nonce-bound body. Because
`metadata` is part of `ChioReceiptIdInput`, the nonce is covered by both the
authoritative `id` and the signature. If `metadata` already holds a non-object
JSON value the producer preserves it under the `original_metadata` key before
inserting the nonce; an empty or whitespace-only pre-binding `id` skips the
binding. The nonce is a fixed point of signing: re-binding an already-bound
body is a no-op because the bound body's `id` is recomputed over the bound
metadata. Every signed `chio.receipt.v1` carries this key, and the inline and
asynchronous kernel signing funnels emit byte-identical receipts because both
apply this same binding through one signing primitive.

The producer canonicalizes that wrapper via RFC 8785 JCS and signs the
resulting bytes with the kernel's identity key. Three signing
algorithms are supported in v1, and verifiers dispatch off the
`signature` field prefix rather than the optional `algorithm` envelope
hint:

- **Ed25519** (default): bare lowercase 128-hex (exactly 64 raw bytes);
  the `kernel_key` is bare lowercase 64-hex (32 raw bytes).
- **P-256 (ECDSA / SECP256R1)**: `p256:<DER hex>` over the same canonical
  bytes; the `kernel_key` is `p256:<130-hex>` (uncompressed SEC1 point,
  65 bytes, leading byte `0x04`).
- **P-384 (ECDSA / SECP384R1)**: `p384:<DER hex>` over the same canonical
  bytes; the `kernel_key` is `p384:<194-hex>` (uncompressed SEC1 point,
  97 bytes, leading byte `0x04`).

The wire pattern is fixed by
`spec/schemas/chio-wire/v1/receipt/record.schema.json`:

```text
signature  -> ^([0-9a-f]{128}|p256:[0-9a-f]+|p384:[0-9a-f]+)$
kernel_key -> ^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$
```

The Ed25519 signature length is exactly 128 hex characters; the P-256
and P-384 hex bodies hold variable-length DER-encoded ECDSA signatures
(roughly 70-72 bytes for P-256 and 104-110 bytes for P-384) and are
validated by length-aware decoders downstream of the schema regex. The
optional `algorithm` envelope hint MAY be `ed25519`, `p256`, or `p384`;
when present it MUST agree with the signature prefix and verifiers
reject mismatches fail-closed. Hybrid post-quantum signatures use the
self-describing prefix shape defined in section 4 and are not part of
this `chio.receipt.v1` algorithm enumeration.

Ad hoc byte concatenation is not a valid signing input. Verifiers
reconstruct the typed wrapper, re-canonicalize it via JCS, dispatch off
the signature prefix to select the correct verification algorithm, and
only then verify the signature against the embedded `kernel_key` (which
itself must agree with the same algorithm prefix).

Replay and deduplication state keys exclusively on `id`. A tampered id cannot
influence replay acceptance because verifiers recompute the id from canonical
receipt content before accepting the signature.

For multi-parent lineage, receipts carry:

- `chainId`
- sorted and deduplicated `parentReceiptIds`, each a parent receipt id
- `parentSetHash = H(canonical(parentReceiptIds))`
- `dagOrdinal`
- HLC triple `{ wallSeconds, logical, kernelId }`

The verifier rejects a child unless its parent descriptors match the signed
parent set, every parent shares the same `chainId`, and
`child.dagOrdinal > max(parent.dagOrdinal)`. This rejects cross-kernel cycles
without relying on one global clock.

### 6.1 Receipt Semantics And Decisions

The v1 receipt shape makes authority structural:

- `mediated_decision` receipts use `boundary_class = prevent`,
  `trust_level = mediated`, and MUST carry a `decision`.
- `trace_observation` receipts use `boundary_class = detect_only`,
  `trust_level = verified`, and MUST omit `decision`.
- `advisory_evaluation` receipts use `boundary_class = advisory_only`,
  `trust_level = advisory`, and MUST omit `decision`.

Only `mediated_decision` + `prevent` + `Allow` may be displayed or exported as
authorization. Trace and advisory records can be evidence, but they are never
authorization receipts.

When present, the decision enum is:

- `Allow`
- `Deny { reason, guard }`
- `Cancelled { reason }`
- `Incomplete { reason }`

The protocol guarantee is that cancelled and incomplete outcomes are preserved
explicitly rather than collapsed into an undifferentiated error state.

### 6.2 Authoritative Spend (execution nonce, atomic hold, mediated-spend profile)

An authorization receipt for a spend-bearing tool call is authoritative only when
it satisfies the structural conjunction of the `chio.mediated_spend.v1` profile:

- The receipt is `mediated_decision` + `prevent` + `trust_level = mediated` with
  `decision = Allow` and no `observation_outcome` (see 6.1).
- Its `budget_authority` metadata names a `hold_id` that was atomically committed
  against the agent's cost-bearing capability and reconciled down to realized
  spend (`authorize` then `terminal.disposition = reconciled`).
- A `chio.execution_nonce.v1` nonce, signed by the same admitted kernel key, is
  bound to the same `subject_id`, `request_id`, `capability_id`, `tool_server`,
  `tool_name`, and `parameter_hash`, and the receipt records that nonce id
  (`budget_authority.execution_nonce_id`). The `request_id` binding is required.
  A binding that omits it (a v1 body minted before request binding) still
  decodes, so a rolling upgrade does not fail at parse time, but it is denied at
  verification. That prevents a nonce from being presented for a different
  request that shares the other five fields.

Advisory (`advisory_evaluation`) records and label-only receipts are never
authorization. A guarantee level (`single_node_atomic`, `ha_linearizable`,
`partition_escrowed`, `advisory_posthoc`) must be truthful to the backing store.

### 6.3 Child Receipts

Nested flows such as sampling, elicitation, and resource reads use
`ChildRequestReceipt`, which records:

- `session_id`
- `parent_request_id`
- `request_id`
- `operation_kind`
- `terminal_state`
- `outcome_hash`
- `policy_hash`
- optional metadata

### 6.4 Receipt Metadata

The shipped metadata surface is extensible JSON. The top-level keys below are
reserved: the kernel writes its typed blocks under them, merges them last, and
rejects a pre-existing collision from caller or hook metadata, so a verifier can
treat a block found under a reserved key as kernel-authored and covered by the
receipt signature. Unknown fields and unsupported schema versions fail closed.

| Key | Written by | Contents |
|-----|------------|----------|
| `chio_receipt_signing_nonce` | signing path | The pre-binding receipt id, folded into the signed body of every receipt (see "Receipt Identity And DAG"). |
| `original_metadata` | signing path | A non-object caller metadata value displaced when the signing nonce is bound. |
| `financial` | kernel | Financial attribution and settlement metadata. |
| `budget_authority` | kernel | Budget-authority lineage for monetary receipts. |
| `channel` | kernel | Streamed-output channel accounting metadata. |
| `governed_transaction` | kernel | Governed-transaction intent and approval metadata. |
| `admission_operation` | kernel | Durable admission projection, schema `chio.admission-receipt.v1` (see below). |
| `delivery_contract` | kernel | Output-digest delivery evidence, schema `chio.delivery-contract.v1` (see below). |
| `finding_delivery` | kernel | Purchased-finding delivery overlay, schema `chio.finding.delivery.v1` (see below). |

Subject and issuer attribution, streamed-output chunk metadata, and
portable-trust and federation provenance are additive extensions layered over
the same object.

Durable tool calls carry an `admission_operation` block whose schema is
`chio.admission-receipt.v1`. It binds the signed receipt to the admission
operation and request namespace, terminal projection and dispatch state,
trusted time, coordinator lease and store fence, retained dispatch commit, and
optional tool outcome. The machine-readable contract is registered at
`spec/schemas/chio-wire/v1/receipt/admission-metadata.schema.json`; unknown
fields and unsupported schema versions fail closed.

Digest-constrained tool calls carry a `delivery_contract` block whose schema is
`chio.delivery-contract.v1`. It records the `expected_digest` the grant fixed in
advance, the `observed_digest` of the delivered output (both canonical lowercase
64-character hex SHA-256), and a `result` of `matched` or `mismatched`. The
block is present only when the exercised grant carried an output-digest
constraint: `matched` accompanies an Allow, `mismatched` accompanies the
persisted zero-charge Deny. Like the admission block it carries no signature of
its own and is authenticated by the enclosing receipt. The machine-readable
contract is registered at
`spec/schemas/chio-wire/v1/receipt/delivery-contract.schema.json`; unknown
fields, a non-pinned schema, and non-hex digests fail closed.

A reveal admitted under a provider-signed finding purchase marker carries a
`finding_delivery` block alongside the generic one, with schema
`chio.finding.delivery.v1`. It names the `finding_id` and `listing_id` the sale
was admitted under, the kernel-proved `transform_profile`, the `digest_check`
and `media_type_check` comparisons, the `settlement_mode` the admitted selector
named, the canonical SHA-256 digests of the accepted-bid and venue-admission
envelopes, and the authoritative `reservation_id`, `purchase_intent_id`, and
`authoritative_payment_operation_id`. Every field derives from kernel-verified
state, never from a caller-asserted value, and the block appears only when the
purchase context arrived through verified signed artifacts. Like the generic
block it carries no signature of its own and is authenticated by the enclosing
receipt. The machine-readable contract is registered at
`spec/schemas/chio-wire/v1/receipt/finding-delivery.schema.json`; unknown
fields, a non-pinned schema, non-hex envelope digests, and unrecognized
comparison, profile, or settlement values fail closed.

Governed receipt metadata now also admits a versioned
`economic_authorization` envelope with `version`, `economic_mode`, `payer`,
`merchant`, `payee`, `rail`, `amount_bounds`, `pricing_basis?`,
`metering?`, `liability_refs?`, `budget`, and `settlement`. The envelope keeps
budget, meter, rail, and settlement truth in separate typed sub-blocks and is
additive only: the compatibility `financial`, `commerce`, `metered_billing`,
`approval`, `runtime_assurance`, `call_chain`, and `autonomy` fields remain
intact for backward compatibility.

Governed transaction receipts use a `governed_transaction` metadata block with
the canonical intent identifiers plus optional approval evidence. The current
block includes:

- `intent_id`
- `intent_hash`
- `purpose`
- `server_id`
- `tool_name`
- optional `max_amount`
- optional `commerce { seller, shared_payment_token_id }`
- optional
  `metered_billing { settlementMode, quote, maxBilledUnits, usageEvidence }`
- optional `approval { token_id, approver_key, approved }`
- optional
  `runtime_assurance { tier, verifier, evidence_sha256, workload_identity? }`
- optional
  `call_chain { evidenceClass, evidenceSources[], assertedContext?,
  continuationTokenId?, sessionAnchorId?, receiptLineageStatementId?,
  upstreamProof?, chainId, parentRequestId, parentReceiptId?, originSubject,
  delegatorSubject }`

`governed_transaction.runtime_assurance.tier` records the accepted runtime
assurance tier after any configured verifier trust-policy rebinding, not just
the raw tier carried by the upstream attestation payload.

When present, `governed_transaction.call_chain` records the strongest
provenance projection Chio is willing to sign for that receipt. The flattened
`chainId`, `parentRequestId`, `parentReceiptId`, `originSubject`, and
`delegatorSubject` fields describe the effective observed or verified
projection. If Chio also needs to preserve the original caller assertion, it
stores that separately under `assertedContext`; downstream consumers must not
collapse `assertedContext` into verified truth.

Settlement reconciliation state is intentionally not written back into the
signed receipt. Trust-control keeps mutable operator-side reconciliation state
keyed by `receipt_id` and reports it separately from the signed
`financial.settlement_status` so receipt truth remains immutable.

The `governed_transaction.metered_billing` block preserves the quoted estimate
and, when later available, a post-execution `usageEvidence` reference. This is
separate from `metadata.financial`, which continues to record the kernel's
charged or attempted amount. Chio does not collapse quoted cost, actual charge,
and external usage evidence into one field.

When post-execution metered evidence arrives from an external adapter, Chio
stores that record in a mutable sidecar keyed by `receipt_id`, carrying the
adapter identity, evidence record identity, observed units, billed amount, and
operator reconciliation state. That sidecar is queryable and exportable, but
it is not merged back into the signed receipt JSON.

Exporter, report, and OpenTelemetry projections are not authoritative receipt
truth unless they embed and verify the full signed `ChioReceipt` envelope.
Projection rows may carry `receipt_id`, derived status, reconciliation state,
or selected metadata for operators, but those fields are telemetry views over
signed receipt truth, not replacement receipts. A consumer that needs
authorization, billing, lineage, or audit authority must verify the signed
receipt or a signed receipt-lineage statement. If the signed source artifact is
missing, stale, malformed, or mismatched with the projection, the consumer must
fail closed and treat the projection as non-authoritative.

### 6.4.1 Provenance Graph Artifacts

The receipt plane now defines one provenance graph substrate even when different
surfaces project different slices of it:

- session anchors capture authenticated session continuity
- request-lineage records capture request nodes and local parent edges
- receipt-lineage statements capture authenticated receipt-to-receipt edges
- continuation tokens capture authenticated cross-kernel or cross-session
  provenance transfer

Receipts prove kernel-observed evaluation events. Receipt-lineage statements
and continuation tokens prove authenticated linkage between those events. None
of these artifacts alone prove external real-world side effects beyond Chio's
observation boundary.

### 6.4.2 Swarm Authority Runtime Admission

Recursive delegation and multi-swarm execution are governed at runtime, not
only in offline proof reports. A protocol or kernel edge that dispatches
swarm-bound child work must verify a stored swarm authority bundle before the
child action can run. Missing, stale, malformed, or mismatched swarm evidence
denies the action.

The admission reference binds the child dispatch to:

- the task graph digest
- the parent or join receipt
- the continuation token
- the delegation witness chain for the hop
- the route-plan receipt
- the revocation epoch id and root hash
- the budget pool allocation or lease

The signed task graph carries explicit structural ceilings: a `maxDepth`
bound on task depth and a `maxFanout` bound on per-parent delegation fan-out
(`SwarmTaskGraph` in `crates/kernel/chio-swarm-authority/src/types.rs`). The
admission verifier enforces both ceilings over the whole graph: any node
whose depth exceeds `maxDepth`, and any parent whose outgoing edge count
exceeds `maxFanout`, rejects the bundle. Edge depth arithmetic is also
checked: every edge target MUST sit at exactly the parent depth plus one, and
depth overflow is a rejection, not a wraparound. Because the ceilings are
part of the signed graph, a planner cannot widen recursion or fan-out after
issuance without invalidating the graph signature.

Continuation tokens are signed by a pinned witness key and bind graph,
route-plan, budget-allocation, revocation-epoch, nonce, and mode. `SingleUse`
continuations are reserved before dispatch and cannot be replayed through the
memory or durable runtime stores. `Resumable` continuations are revalidated on
resume without being treated as single-use replay.

Route metadata is mandatory for swarm-bound dispatch. Runtime admission accepts
the current edge metadata spellings `route`, `route_selection`, and
`routeSelection`, then compares the selected route, bridge, and protocol target
against the verified route-plan receipt. Omitting route metadata is a denial,
not a way to bypass route-plan enforcement.

Budget fan-out and fan-in use explicit reservation and release transitions.
Allocations carry dimension id, state, reserved units, active units, consumed
units, released units, and reversed units. Admission rejects inactive or
replayed allocations, and terminal graph receipts reconcile the final rollup
against the budget pool.

Offline proof-bundle verification (`chio proof verify`) requires signed swarm
delegation evidence and rejects a root-only swarm proof fail-closed. Even when
the task graph, budget pool, and revocation epoch are otherwise valid and
signed, a bundle whose continuation-token or delegation-witness-chain roles are
empty is denied (`signed swarm delegation evidence missing`); the verifier
emits no swarm claim for a bundle it rejects. Absent delegation evidence is a
denial, not a suppressed-claim acceptance, consistent with the fail-closed rule
that incomplete swarm authority is denied rather than partially trusted.

The bounded conformance surface for this release covers recursive-delegation
positive fixtures, generated malformed graph, budget, epoch, route, and
terminal-rollup cases, plus edge-dispatch checks for MCP, A2A, ACP-Client, OpenAI
function-call execution, and OpenAPI bridge dispatch. This remains a bounded
runtime-admission contract. Listing or exporting swarm evidence does not widen
runtime authority unless the admission verifier accepts the current stored
bundle and pinned witness keys.

### 6.4.3 Transaction Passport Proof Root

`chio.transaction-passport.v1` is the canonical launch proof root. A verifier
MUST treat the passport as a signed RFC 8785 canonical JSON envelope over one
transaction graph, not as advisory metadata. The proof root binds:

- root identity fields: `schema`, `id`, `subject`, `transaction_kind`,
  `issuer`, `issued_at`, `expires_at`, and `signature`
- verifier-owned trust material: `trust_roots`, trusted issuer keys, and the
  verifier policy digest
- artifact closure: `artifact_refs`, `evidence_graph_path`,
  `evidence_graph_sha256`, `verifier_policy_path`,
  `verifier_policy_sha256`, `claim_set_path`, and `claim_set_sha256`
- omission policy entries for verifier-policy-declared missing claims

During the v1 fixture transition, fields not yet present as root-level schema
properties MUST still be represented by digest-bound graph artifacts or remain
unproved. A verifier MUST NOT infer a subject, transaction kind, trust root, or
artifact reference from filenames, directory layout, or bundle-local prose.

The evidence graph is a bounded DAG. Every node MUST have a schema id, bundle
relative path, role, and SHA-256 digest; every edge MUST identify source,
target, predicate, and evidence class. Graph verification rejects path escapes,
missing artifacts, digest mismatches, cycles, duplicate required roles,
unbound root artifacts, and unsupported roles. Claim-set digest verification is
performed over the loaded claim-set bytes, not just over the passport field.

`chio.transaction.claim-set.v1` inventories the verifier claims required for
the passport root and the domain family reports. Claim statuses are explicit:
`verified` means the referenced verifier accepted the claim, omitted claims
must be listed in both verifier policy and the signed passport omission policy,
and any unsupported status is a rejection. A claim-set self-report cannot
satisfy a domain claim such as risk, commerce, disclosure, swarm, settlement,
or agent-web; the corresponding external family report MUST supply the
accepted claim before the merged transaction verifier report may be accepted.

The transaction verifier emits registered transaction failure codes for root
failures: `transaction_passport_schema_unsupported`,
`transaction_passport_hash_mismatch`, `transaction_graph_not_closed`,
`transaction_graph_cycle`, `transaction_required_claim_missing`,
`transaction_artifact_hash_mismatch`, `transaction_identity_not_bound`,
`transaction_authorization_not_bound`, `transaction_receipt_uncheckpointed`,
`transaction_runtime_proof_rejected`, `transaction_buyer_review_rejected`,
`transaction_settlement_unverified`, `transaction_dispute_unbound`, and
`transaction_transparency_preview_not_allowed`. A proof surface that collapses
these failures into a generic success state fails the protocol.

### 6.4.4 Commerce Order And Settlement Family

The commerce family is the launch proof lane for autonomous commerce
coherence. `chio.commerce.order-context.v1` binds one order id to buyer,
agent, merchant or provider subjects, current order state, quote, provider
admission, mandate allowance, payment lifecycle, settlement packet,
reconciliation, and event-log digests. `chio.commerce.order-passport.v1` is
the selective public summary over the same order; it MUST NOT be accepted
unless its artifact digests match the order context and the verified claim set.

The order event log is a monotonic state-transition ledger. Each event MUST
bind an idempotency key, actor, prior state, next state, transition, occurred
time, authority receipt reference, event digest, and evidence references. A
verifier rejects missing authority receipts, duplicate event ids, skipped
states, backwards state transitions, inconsistent order ids, and event-log
digests that do not match the order context.

Payment and mandate artifacts are subordinate evidence, not ambient authority.
`chio.commerce.payment-lifecycle.v1` binds payment status, capture, dispute,
fraud, transfer, amount, currency, PSP references, and quote digest.
`chio.commerce.mandate-allowance-ledger.v1` binds maximum amount, currency,
validity window, single-use or occurrence limits, protocol payload digests, and
usage count. `chio.commerce.settlement-packet.v1` binds settlement dispatch,
reconciliation, destination, amount, currency, and external settlement
references. AP2, x402, ACP-Commerce, or PSP payloads are accepted only as
digest-bound protocol payload evidence named by the mandate or payment
artifact; they do not replace Chio receipts or widen payment authority.

Commerce verification fails closed on currency drift, amount drift,
merchant/provider mismatch, untrusted provider evidence, expired or overused
mandates, missing authority receipts, PSP status that does not support the
claimed state, settlement packet mismatch, duplicate completion, or a public
order passport whose summary digests do not match the private order context.

### 6.4.5 Disclosure And Lineage Family

The disclosure family is the launch proof lane for constrained reveal.
`chio.disclosure.capsule.v1` binds a disclosure policy, source artifact
digests, reveal set, redaction or hidden-field commitments, verifier privacy
profile, leakage ledger reference, issuer, subject, and signature.
`chio.lineage.signed-subgraph.v1` binds the disclosed lineage edges that justify
the reveal. Disclosure verification accepts only the facts allowed by the
verifier policy and rejects excess fields, missing required revealed fields,
policy digest drift, stale or untrusted lineage signer keys, and hidden
predicate claims that are not implemented by the capsule.

Disclosure artifacts do not downgrade receipt authority. A revealed fact that
claims authorization, payment, settlement, risk, or runtime authority MUST be
backed by the corresponding signed receipt, transaction claim, or family
report. The signed lineage subgraph preserves evidence class. `verified`,
`observed`, `asserted`, `unverifiable`, and `rejected` edges are distinct, and
an asserted edge MUST NOT satisfy a verifier requirement for verified lineage.

Leakage ledgers and crypto-context reports are verifier inputs to privacy
evaluation. They may record what was revealed, when, under which profile, and
which crypto context or BBS material was used. They do not authorize additional
fields, silently repair an over-disclosure, or make absent signatures trusted.

### 6.4.6 Agent Web Envelope Family

`chio.agent-web-proof-envelope.v2` is the current projection envelope for
external protocol objects. It binds one source protocol and version, one
external subject path and digest, unique Chio receipt references, a transaction
passport reference and canonical passport-scope digest, a projection manifest
reference and digest, optional settlement, risk, and disclosure references,
limitation text, Chio claim references, and the envelope signature. The scope
digest and corresponding receipt action bindings prevent an envelope from being
replayed against a different passport scope, manifest, source protocol, or
source version. The envelope is accepted only with
`chio.agent-web.external-projection-manifest.v1` and
`chio.agent-web.interop-verifier-report.v1` for the same projection.

`chio.agent-web-proof-envelope.v1` remains a verification-only compatibility
format. Its published schema and canonical signed payload do not contain the
passport-scope digest, and legacy duplicate receipt references remain valid at
the schema boundary. New producers MUST emit v2. Verifiers that accept v1 MUST
use the v1 canonical identifier and signature payload, require the legacy
receipt-to-envelope bindings, and MUST NOT reinterpret v1 as carrying v2 scope
authority.

The projection manifest declares which external fields were used, which were
not used, the digest algorithm, source protocol version, sidecar-bound fields,
claim mapping, unsupported claims, copy limitations, and whether an external
signature is required. The interop verifier report MUST recompute external
subject digests, enforce source-version-specific required fields, bind receipt
and passport references, and mark unsupported native-authority claims as
limited. Missing external subjects, digest mismatches, source-version drift,
unsupported claim overreach, and sidecar-only evidence presented as native
protocol authority are rejections.

Agent Web projections are not adapters with ambient Chio authority. MCP, A2A,
ACP-Client, ACP-Commerce, AG-UI, OpenAPI, AP2, x402, Kubernetes admission,
GraphQL, CloudEvents, in-toto, SLSA, Sigstore, browser automation, email,
Slack, SCIM, and related protocols remain external systems. Chio proves the
digest-bound relationship between those objects and Chio receipts; it does not
claim those protocols natively enforce Chio policy unless the runtime adapter
path separately verifies authority and emits receipts.

### 6.4.7 Finding Artifact Family

`chio.finding.v1` is the signed information-good artifact for cognition-market
findings. It binds a machine-matchable descriptor, a commitment to the reveal
envelope, evidence references and cost, guarantee and evidence classes, bond
and status references, an Ed25519 issuer, and a validity window. Its
`finding_id` is the SHA-256 digest of canonical JSON for the artifact after
setting both `finding_id` and `signature` to the empty JSON string `""`.
Those members remain present; implementations MUST NOT omit them or encode
them as `null` in the id preimage. Its inline signature covers canonical JSON
after retaining the populated `finding_id` and setting only `signature` to
`""`, again without omitting the member. The signature therefore binds the
content-addressed identifier.

Finding artifacts MUST use the bare lowercase Ed25519 key and signature
encodings required by the registered schema. Issuer verification MUST reject
weak, low-order Ed25519 keys and use strict signature verification.
`evidence_cost.currency` MUST be a three-letter uppercase ISO 4217-style code.
Integer-valued cost and timestamp fields MUST remain within the I-JSON safe
range. An absent
`runtime_assurance_tier` is the sole encoding for no runtime assurance.
`deterministic_replay` findings MUST carry `replay_recipe_sha256`. Any
non-asserted guarantee or evidence class, or any present runtime assurance
tier, MUST carry at least one evidence receipt reference. Evidence receipt
identifiers MUST be unique within an artifact.

Artifact verification proves structural invariants, content-address binding,
and the embedded issuer signature. It does not authenticate referenced
receipts or checkpoints, bind issuer identity to evidence lineage, verify
bonds, status feeds, or pricing hints, check wall-clock liveness, or establish
the truth of a guarantee or evidence class. A market or trust decision MUST
perform those checks separately before relying on the corresponding claim.

#### 6.4.7.1 Market envelope discipline

Fourteen families travel as signed export envelopes
(`{body, signerKey, signature}`): `chio.finding.challenge-verifier-profile.v1`,
`chio.finding.market-terms.v1`, `chio.finding.seller-authorization.v1`,
`chio.finding.bond-backing.v1`, `chio.finding.verifier-report.v1`,
`chio.finding.admission.v1`, `chio.finding.purchase-record.v1`,
`chio.finding.failed-delivery.v1`, `chio.finding.challenge.v1`,
`chio.finding.challenge-outcome.v1`,
`chio.finding.challenge-enforcement.v1`,
`chio.finding.finalized-bond-snapshot.v1`,
`chio.finding.audit-epoch.v1`, and `chio.finding.audit-report.v1`. This
differs from the inline-signed
`chio.finding.v1` and from the unsigned
`chio.finding.replay-recipe-input.v1`,
`chio.finding.purchase-context.v1`, and
`chio.finding.replay-observation.v1`, which carry no envelope at all. Each
of the fourteen envelope bodies is strict snake_case JSON that rejects
unknown members and carries a stable identifier. Twelve of them are
content-addressed exactly like `finding_id`: the SHA-256 digest of
canonical JSON for the body after setting only the id member to the empty
JSON string `""`, with every other member present. Two are exceptions:
`chio.finding.purchase-record.v1` derives its `purchase_key` from a
domain-separated preimage over two members (6.4.7.10), and
`chio.finding.challenge-outcome.v1` derives its `outcome_id` from a
domain-separated preimage over the whole canonical body (6.4.7.13). The
first six additionally name their own signing authority in the body, as
does a `buyer_submission` challenge through its `challenger`; the two
purchase terminals, a `venue_audit` challenge, and the five remaining
challenge and audit artifacts name other subjects and are authorized only
by the external role pin. Envelope
verification
MUST verify strictly against an EXTERNALLY pinned authority key, MUST
reject weak Ed25519 keys, MUST require the embedded `signerKey` to equal
the pinned authority, and MUST require the body's authority member, where
one exists, to equal the envelope signer. Verifying an envelope against
its own embedded key alone is never sufficient for any market or
value-moving decision.
Envelope digests referenced by other artifacts are SHA-256 over the
canonical JSON of the COMPLETE envelope (body, signer key, and signature),
never over the body alone.

#### 6.4.7.2 `chio.finding.challenge-verifier-profile.v1`

The reusable, governance-signed trust profile. It binds receipt signer
roles (production, delivery, replay, each exactly once), checkpoint log
identities and signers, the externally trusted BBS projection issuer and
registry, allowed runner manifest digests, required receipt semantics,
resolver and retention policy references, resource caps, the predicate
engine and its closed predicate vocabulary
(`baseline_fails_candidate_passes_v1` at this stage), the verifier-report
signer role, the purchase and failed-delivery authority roles, per-key
epoch, validity, rotation, and revocation policy, the operator, and a
validity window. The profile has no member that can reference a finding,
recipe, listing, report, or backing: a finding-scoped profile would form
a hash cycle and is invalid. Role keys named here are additionally pinned
by deployment governance; presence in a profile authorizes nothing by
itself.

#### 6.4.7.3 `chio.finding.replay-recipe-input.v1`

The UNSIGNED strict replay verifier input. It registers in the public
schema registry and manifest but MUST NOT enter the signed-artifact
allowlist; it travels only as a content-addressed non-authority
attachment. Its integrity comes from bytes: a `deterministic_replay`
publication MUST supply a size-bounded strict raw preimage whose canonical
digest equals the signed finding's `replay_recipe_sha256`. Duplicate keys,
unknown members, non-canonical spellings, and digest mismatches reject.
The input binds the decision rule, the admitted verifier-profile envelope
digest, finding context and payload commitments, the mediated runner and
manifest, ordered baseline-then-candidate phases with immutable input
bundles and exact payload-application semantics, a canonical parameter
bundle digest, a fully deterministic environment policy, resource bounds,
the closed predicate, the cycle-free pre-run template digest, and the
claimed verdict. The pre-run template commits everything knowable before
execution and excludes the final payload digest, producing receipts,
outcome class, and verdict. Venues MUST retain the recipe and every
digest-addressed dependency through the full claim, audit, and appeal
horizon.

#### 6.4.7.4 `chio.finding.market-terms.v1`

Seller-signed sale terms: the exact finding and listing, the canonical
backing requirement (`base_finding_stake`, `maximum_sale_exposure`, and
collateral policy, one currency), nonzero filing, claim, and appeal
windows, the audit epoch length, audit eligibility, decision rules, the
admitted verifier-profile envelope digest, per-guarantee-class challenge
bond limits, and a deterministic payout policy. Terms MUST NOT bind the
later backing-envelope digest; backing may bind terms, so the reverse edge
would form a cycle. The envelope signer MUST equal the embedded seller.

#### 6.4.7.5 `chio.finding.seller-authorization.v1`

Finding-issuer-signed authorization for a seller or delegate: the exact
finding, listing, seller, provider server and tool, the payment
beneficiary or a provider-signed payee mapping digest, a revocation
status reference, and a validity window. This artifact is REQUIRED even
when issuer and seller are the same key. The envelope signer MUST equal
the embedded issuer, and surfaces that resolve the finding MUST also
require that issuer to equal the finding's issuer.

#### 6.4.7.6 `chio.finding.bond-backing.v1`

Collateral-authority-signed live allocation: seller, authorization,
finding, listing, terms and profile envelope digests, the exact
fee-schedule envelope and bond-requirement digests, the `listing` bond
class, one currency, a locked amount that is at least the maximum sale
exposure, nonzero claim, audit, appeal, and settlement horizons, the
concrete vault (the `venue_ledger` variant at this stage; unknown vault
kinds reject), and an expiry. A signed requirement, an opaque reference,
or a transient evaluation result is NOT collateral: admission MUST resolve
the allocation to live, exclusive, unconsumed store state, and reused,
stale, wrong-party, wrong-currency, or underfunded allocations reject.

#### 6.4.7.7 `chio.finding.verifier-report.v1`

Verifier-authority-signed facet report: the exact finding id and artifact
digest, verifier profile id and envelope digest, verifier implementation
id, resolved-evidence bundle digest, trust-root, resolver, and
trusted-time input digests, exactly the thirteen facets in canonical
order (`artifact_integrity`, `receipt_authenticity`,
`checkpoint_membership`, `kernel_and_revocation_trust`, `issuer_lineage`,
`recipe_binding`, `intent_binding`, `metered_exposure_backing`,
`settled_spend_backing`, `runtime_assurance_backing`, `bond_backing`,
`status_liveness`, `guarantee_consistency`), each `verified`, `asserted`,
`unavailable`, or `failed` with a reason, the verifier key epoch, and the
evaluation time. A `verified` `bond_backing` facet MUST name the exact
backing allocation, and acceptance MUST reject a report whose named
allocation did not exist before the report's evaluation time. A `failed`
facet MUST always deny. Every facet required by the profile or by a present
finding claim MUST be exactly `verified`; `asserted` and `unavailable` deny
when that facet is required. Only the externally
pinned, profile-authorized verifier key that was valid and unrevoked at
evaluation may sign.

#### 6.4.7.8 `chio.finding.admission.v1`

The venue-signed admission bundle, the ONLY qualification of a finding
listing for trusted search, bid, and purchase. It binds the exact finding
artifact digest, seller-authorization, listing, pricing-hint, terms,
profile, verifier-report, and backing envelope digests, the exact backing
allocation id, the capability scope `finding:<finding_id>` exactly, the
server, metadata URL, publisher, and payee, the fee-schedule envelope
digest, settled fee terminals
(publication plus the first participation epoch at minimum, each naming
schedule, event, payer, amount, pool principal, rail destination, and the
rail evidence digests), the distinct audit-pool and
challenge-administration-pool principals with rail-tagged destinations and
authority epochs, the community-fund destination, the status-feed
operator reference, the purchase and failed-delivery authority snapshots,
and a validity window. The body venue identity and the envelope signer
MUST both equal the externally configured venue authority. Admission
expiry MUST be no later than the earliest constituent expiry. Publication
liveness uses both bounds: a finding with `issued_at > now` or
`expires_at <= now` MUST NOT be indexable, admittable, or pairable with a
fresh pricing hint.

#### 6.4.7.9 `chio.finding.purchase-context.v1`

The UNSIGNED bounded carrier a buyer presents at reveal admission. Like the
replay-recipe input, it registers in the public schema registry and manifest
but MUST NOT enter the signed-artifact allowlist. It holds the exact
canonical JSON TEXT of the signed finding, the listing, pricing-hint,
admission, terms, seller-authorization, verifier-profile, backing, and
verifier-report envelopes, the bid-request, ask-response, accepted-bid, and
reservation-receipt envelopes, the authoritative reservation store key, and
the capability token offer. Members stay opaque text because the token is
compared for BYTE identity against the token the ask embedded, and a typed
round-trip would normalize that comparison away. A presentation MUST be
rejected before decoding when it exceeds the encoded bound, and after
decoding when it exceeds the canonical bound, when the decoded bytes are not
byte-identical to their own strict canonicalization, when any member is
absent, oversized, or not itself strictly canonical, or when the carried
members together exceed the carrier bound. The carrier authorizes nothing:
the reveal path MUST re-verify every member from its bytes.

#### 6.4.7.10 `chio.finding.purchase-record.v1`

The purchase-authority-signed record of one settled sale: the purchase
intent, the authoritative payment operation, buyer and payer keys, the exact
finding, listing, accepted-bid envelope, venue-admission envelope, and
seller-backing envelope digests, the accepted price and the realized spend
in one currency, the encumbrance, the delivery receipt, the payment
reference, a rail-tagged payout destination, and the record time. Its
`purchase_key` is the SHA-256 digest of the domain-separated preimage
`"chio.finding.purchase.v1\0"` followed by the accepted-bid envelope digest,
a NUL byte, and the authoritative payment operation identifier. That key is
the settling store's idempotency key: a retry of the same sale MUST
recompute the same key, and a second payment operation for the same bid MUST
NOT reuse it. `realized_spend` MAY fall below `accepted_price` for a partial
capture but MUST NOT exceed it, and both amounts MUST share one currency.

#### 6.4.7.11 `chio.finding.failed-delivery.v1`

The failed-delivery-authority-signed terminal for a reveal denied before any
value moved. It binds the buyer, the exact finding, listing, and
accepted-bid envelope digest, the reservation, purchase intent, and
authoritative payment operation, the exact hold attempt and its release
terminal (`released` or `cancelled_before_authorization`; unknown terminals
reject), both halves of the deny evidence (receipt identifier and digest,
checkpoint reference and digest), the currency, and the record time. Its
`realized_spend_units` MUST be zero and its `payout_eligible` MUST be false;
both are encoded rather than implied so a spend on this path is a
schema-level rejection rather than a reconciliation surprise. Silence is not
evidence: without this signed terminal a released hold is indistinguishable
from a captured one.

#### 6.4.7.12 `chio.finding.challenge.v1`

The signed submission that opens a dispute against one admitted listing.
Common members bind the challenge, the finding and its artifact digest, the
listing, the admitted terms, verifier-profile, and seller-backing envelope
digests, the filing time, and a size-bounded `affected_deliveries` set whose
entries are atomic `{receipt_id, receipt_sha256, checkpoint_ref,
checkpoint_sha256}` tuples. Those entries MUST NOT carry a buyer identity,
an amount, or a payout address: they establish standing, and the payout set
is derived from the authoritative purchase index at the frozen cutoff.

Two independent closed unions gate the submission, and both MUST be enforced
by the registered schema and by artifact validation. The authorization union
is exactly one of `buyer_submission`, naming the challenger that MUST equal
the envelope signer, the settled dispute-fee terminal payable to the
admission-pinned challenge-administration pool, the live exclusive `dispute`
lock, and class-specific standing, or `venue_audit`, naming the signed audit
epoch envelope digest, the selection digest, and the authorization digest.
A `venue_audit` has no challenger, lock, fee, forfeiture, or reward member
at all, and a `buyer_submission` has no audit member; a cross-branch member
rejects at parse time. A `buyer_submission` MUST carry at least one affected
delivery, and its standing branch MUST match its evidence class and name the
same artifact digest that class binds: `failed_delivery` standing pairs only
with `digest_mismatch`, and `finalized_purchase` standing only with
`evidence_invalid` or `replay_contradiction`.

The evidence union is exactly one of `digest_mismatch`, naming the signed
failed-delivery envelope digest plus the deny receipt and checkpoint
references, `evidence_invalid`, naming the contested receipt subset, the
challenged checkpoint reference, and the finalized purchase-record envelope
digest, or `replay_contradiction`, naming an ordered size-bounded
reproduction set, the strict canonical
`chio.finding.replay-recipe-input.v1` preimage, and the purchase-record
envelope digest. Every reproduction tuple is
`{receipt_ref, checkpoint_ref, observation_bytes}`; the observation bytes
MUST be strict canonical `chio.finding.replay-observation.v1`, every tuple
MUST share one `replay_run_id`, and every observation MUST commit the
digest of the carried recipe preimage and the verifier profile the
challenge names. Loose identifiers, a single checkpoint for unrelated
receipts, non-canonical preimages, and digest mismatches reject before
evaluation.

The guarantee/evidence compatibility matrix is closed and normative, and it
requires the challenged finding, which this artifact binds only by digest:
`digest_mismatch` admits any guarantee and evidence class because its
standing is the signed failed-delivery terminal; `evidence_invalid` requires
an `observed` or `verified` evidence class; `replay_contradiction` requires
`deterministic_replay` and `verified`. Every other pairing MUST reject
before evaluation.

#### 6.4.7.13 `chio.finding.challenge-outcome.v1`

The evaluator-signed verdict. The class-independent `verdict` is exactly
`upheld`, `rejected`, or `indeterminate`, and the third member is required
whenever authority, retention, resolver, or infrastructure inputs cannot be
established. An indeterminate outcome MUST create no hold, sanction,
liability transition, audit reward, or forfeiture, and only `upheld` may
enter the penalty lane. The body binds the exact signed challenge ENVELOPE
digest; a digest over the challenge body alone is a different identity and
MUST reject. It further binds the finding, listing, and backing allocation,
the authorization branch and evidence class tags, the verifier-profile
envelope and evidence-bundle digests, the nested class facet, a reason, the
trigger digest, the evaluator key epoch, and the evaluation time.

The facet is nested beneath the evidence branch that produced it and MUST
match the class tag. The `digest_mismatch` facet carries the committed and
delivered digests, a `transform_profile` of exactly `identity`, and a zero
realized spend, so generic mismatch and operator-policy transform denials
can never sanction the seller; an `upheld` verdict additionally requires the
two digests to differ. The `evidence_invalid` facet carries the contested
receipt identifiers and a closed invalidity result, where only affirmative
invalidity upholds, a resolved and valid subset rejects, and unavailable
inputs are indeterminate. The `replay_contradiction` facet carries the run,
the recipe digest, the committed predicate, its
`confirmed_contradiction | consistent | indeterminate` result, and the
observation digests; that result maps in that order onto `upheld`,
`rejected`, and `indeterminate`, and the body's verdict MUST equal the
mapped value.

A checked penalty calculation is present exactly when the verdict is
`upheld`. It records the base stake, the open per-sale encumbrances, the
computed exposure, the signed listing requirement, the live allocated
collateral, and the resulting amount and currency:
`computed_exposure = base + encumbrances` with checked arithmetic, an
exposure above the signed requirement MUST reject rather than clamp, and the
amount MUST equal `min(live_allocated_collateral, computed_exposure)`.

`outcome_id` is the SHA-256 digest of the domain-separated preimage
`"chio.finding.challenge-outcome.v1\0"` followed by the canonical JSON of
the body with only `outcome_id` set to `""`. The envelope signature lives
outside the body and is excluded by construction, which is what lets the
penalty lane bind `reference_id` to `outcome_id` and `sha256` to the signed
envelope digest as two independent facts.

#### 6.4.7.14 `chio.finding.challenge-enforcement.v1`

The venue finalization authority's signed instruction to impair one seller
allocation. It binds the liability key, the finding and listing, the exact
outcome id and outcome, penalty, and bond-snapshot envelope digests, the
sealed purchase-snapshot and deterministic-allocation digests, the seller
allocation, the vault (`chain_id`, `vault_contract`, `vault_id`), the total
amount, the ordered destination list, the semantic effect-intent
identifiers, and the finalization time. Destinations MUST be distinct, MUST
carry nonzero shares in the one enforcement currency, and MUST sum EXACTLY
to the total. Exact-sum checking alone does not prove harmed-party
destinations; the settlement choke point applies the operator policy
allowlist on top.

Effect intents are domain-keyed and carry at most one entry per kind. The
`seller_impair`, `root_intent`, and `retraction` intents MUST all be present,
because each must be durable before any external impairment; `challenge_bond`
and `fee` are present only when the lane collected them.

Publisher-only state is EXCLUDED by construction: this artifact has no
member for an assigned operator sequence, an attempt key, prepared calldata,
or a transaction nonce. Those values are chosen after this artifact is
signed, when the publisher acquires the strict-next sequence lease, and the
attempt key derives from the root intent id and the assigned sequence at
publication time.

#### 6.4.7.15 `chio.finding.finalized-bond-snapshot.v1`

The settlement observer's signed reading of one allocation at one finalized
block: chain, vault contract and id, seller, allocation, the locked, held,
and slashed amounts in one currency, the block number and hash, the finality
policy and the observed finality (`finalized`, or a nonzero confirmation
depth), the observing operator's identity registry record, key hash, and key
epoch, and the observation time. The block number MUST be nonzero, hashes
MUST be 32 bytes of lowercase hex with an optional `0x` prefix, and
`held + slashed` MUST NOT exceed `locked`. A signed allocation states what
was promised; only this snapshot states what the chain held.

#### 6.4.7.16 `chio.finding.audit-epoch.v1`

The venue's signed precommitment for one audit round, published BEFORE any
listing is selected: the epoch index, the eligible listing snapshot digest
and count, the fee-schedule envelope digest, the seed COMMITMENT, the
selection algorithm, the published rate in basis points (nonzero and at most
10000), the available budget, the governance authorization digest, and the
commitment time. The seed itself has no encoding in this artifact and MUST
NOT be published with its commitment.

Under the selection algorithm `chio.finding.audit-selection.weighted-draw.v1`
each eligible listing draws the SHA-256 digest of the domain-separated
preimage `"chio.finding.audit-draw.v1\0"` followed by the revealed seed, a
NUL, the finding identifier, a NUL, and the listing identifier. Listings are
ordered by the rational priority `draw / weight`, smallest first, where an
absent weight is exactly 1 and the draw is the WHOLE digest read big-endian.
Implementations MUST compare by cross multiplication over every bit of both
draws rather than over any prefix of them, and MUST break an exact tie by
ascending finding identifier. The round takes the first targets, counting the
published rate over the eligible count rounded UP. A prefix comparison would
make distinct draws tie, settle those rounds on the finding identifier
instead, and shrink the target a venue that also chooses the weights has to
grind for from the whole digest down to that prefix.

#### 6.4.7.17 `chio.finding.audit-report.v1`

The venue's signed result for the same round, published AFTER the reveal: the
exact signed epoch ENVELOPE digest, the revealed seed, the selected finding
identifiers, the attempt receipt identifiers, the missed attempts with their
reasons, the outcome envelope digests, and the report time. The revealed seed
MUST reproduce the epoch's commitment as the SHA-256 digest of the
domain-separated preimage `"chio.finding.audit-seed.v1\0"` followed by the
seed. Every missed attempt MUST name a selected finding, and a round with a
selection that is not fully accounted for by misses MUST carry at least one
attempt receipt. The epoch and the report are two artifacts, never one
mutable one: without both, a published audit rate is an operator assumption
rather than an enforceable one.

#### 6.4.7.18 `chio.finding.replay-observation.v1`

The UNSIGNED strict preimage one replay execution emits for one phase. Like
the replay-recipe input, it registers in the public schema registry and
manifest but MUST NOT enter the signed-artifact allowlist. It binds the
recipe and verifier-profile digests, the committed phase (`baseline` or
`candidate`), the runner manifest, resolved input bundle, and environment
digests, the terminal result (`completed`, `failed`, `timed_out`,
`resource_exhausted`, or `runner_error`), the process exit status, the
report digest, and the `replay_run_id` shared by every phase of one run. The
mediated replay receipt's `content_hash` MUST equal the canonical digest of
these bytes. Only a `completed` observation may feed a predicate; every other
terminal is an infrastructure fact and MUST resolve indeterminate rather than
seller fraud. The observation has no member for a claimed verdict: the
predicate belongs to the committed recipe.

The `environment_digest` binds the execution environment the recipe
committed, and its derivation is normative so that a producer and a verifier
cannot disagree about the value. It is the SHA-256 digest of the canonical
JSON bytes of the committed `chio.finding.replay-recipe-input.v1`
`environment` member, the same derivation the pre-run template digest uses
over its own canonical body. A digest over the whole recipe, over the
runtime image alone, or over any runner-local rendering of the environment
is a different value and MUST reject. An observation whose
`environment_digest` does not equal that commitment ran outside the
committed environment, so it is NOT evidence of seller fraud: like a
non-`completed` terminal it MUST NOT feed a predicate and MUST resolve
indeterminate.

#### 6.4.7.19 `chio.registry.market-penalty.v1`

The open-market penalty artifact, registered publicly by the finding
challenge lane without any change to its frozen fields or enums. Unlike the
finding families, its body is camelCase and TOLERATES unknown members, so
the registered schema uses camelCase member names and MUST NOT close the
body; the envelope around it remains strict. An `upheld` challenge outcome
maps to `abuse_class` `fraudulent_listing` with exactly one `external`
evidence reference whose `reference_id` equals the `outcome_id` and whose
`sha256` equals the canonical signed-outcome ENVELOPE digest. A body-only
digest, an absent `sha256`, a generic or duplicated external reference, a
wrong abuse class, untyped evidence, and signer substitution all reject. The
envelope signer, the body `issued_by`, and the configured governing operator
MUST all name the same profile-authorized penalty authority; a generic
caller-supplied trusted signer is not authorization.

The finding family registers `chio.finding.v1`, the fourteen signed
artifacts above, the three unsigned carriers, and the open-market penalty
envelope at this stage. Status-epoch artifacts remain unsupported until a
future revision of this specification defines and registers them.

### 6.5 Checkpoints

Receipt batches can be committed to a Merkle checkpoint. New issuers use:

```text
chio.checkpoint_statement.v2
```

The v2 signed body may carry `chain_root`, the RFC 6962 commitment over the
checkpoint chain. `chio.checkpoint_statement.v1` checkpoints remain valid for
legacy verification and evidence import, but a v1 body MUST NOT carry
`chain_root`. New cryptographic prefix proofs use
`chio.checkpoint_consistency_proof.v2`; the v1 consistency record remains a
legacy metadata-only continuity record and MUST NOT be interpreted as a
cryptographic prefix proof. Checkpoint verification is part of exported
evidence and compliance-oriented operator reporting. Chio's web3 anchoring and
settlement lanes additionally require durable local receipt storage and
kernel-signed checkpoint issuance; append-only remote receipt mirrors are
insufficient when the runtime claims Merkle or Solana evidence readiness.

A checkpoint set presented without a separately pinned boundary MUST carry the
predecessor chain back to checkpoint 1. A checkpoint that cites a predecessor
absent from the set MUST fail verification. Scoped evidence exports therefore
include the checkpoint prefix through the newest checkpoint covering the
selected receipts.

The registered `chio.transparency.inclusion-proof.v1` format retains its
selective-disclosure hash construction and does not qualify a transaction as
`trust_anchored`. The checkpoint-anchored receipt format is
`chio.transparency.inclusion-proof.v2`: it uses RFC 6962 leaf and node hashing,
binds the leaf to the transaction receipt bytes, and embeds a strictly parsed
checkpoint statement signed by a verifier-pinned checkpoint key. Readers MUST
NOT interpret v1 proof bytes with the v2 trust semantics.

The current bounded release treats checkpoints as local audit evidence with
derived `log_id`, `log_tree_size`, predecessor-witness, and consistency-proof
surfaces. Those proofs support audit and `transparency_preview` claims only.
They do not yet justify public append-only or strong non-repudiation language,
because checkpoint leaves still cover checkpointed tool-receipt batches rather
than the full claimed receipt family, and external trust anchors or publication
paths remain optional rather than required.

On qualified paths, a checkpoint publication record may additionally carry a
declared trust anchor, signer-chain reference, and publication-profile version.
That optional `trust_anchor_binding` may now also carry typed
`publication_identity` and `trust_anchor_identity` declarations to identify the
intended publication surface and verifier root family. These fields remain
descriptive until a verifier independently checks the declared publication path;
they do not by themselves prove witness acceptance, immutable publication, or
external real-world side effects.
When all three validate, Chio may say that the checkpoint was published under
declared trust anchors and publication policy. That is a trust-anchored
publication statement, not an `append_only` promotion.

In claim-boundary terms, `audit_only` remains local signed checkpoint evidence,
`transparency_preview` remains the default continuity class for bounded preview
surfaces, and trust-anchored publication is a narrower descriptive boundary
inside that preview tier unless the full append-only gate is met. Chio MUST NOT
use public append-only or strong non-repudiation language until the published
surface is claim-complete, child-receipt-complete, anti-equivocation-capable,
and qualified under the declared verifier policy.

### 6.5.1 Anchor Batch v1

`chio.anchor_batch.v1` is an additive batch artifact. It builds a Merkle tree
over receipt or checkpoint IDs, signs the batch root and inclusion proofs, and
binds the root to a public witness lane:

- `rekor`
- `ots`
- `solana_memo`

Per-receipt local signatures remain the authority for individual receipts. A
batch root upgrades continuity and public timestamping, but a witness outage
does not invalidate locally verifiable receipts.

Batch verifiers fail closed on:

- forged batch roots
- inclusion proofs that do not match the checkpoint at the same index
- witness entries whose root differs from `treeRoot`
- witness lanes outside the verifier allow-list

When all witness lanes are unavailable beyond the configured freshness window,
new batches degrade to `pending_public_witness`. Verifiers configured with
`require_public_witness` reject those new batches while continuing to accept
already-witnessed batches and locally valid receipts. The operational semantics
are pinned in `docs/security/public-witness-semantics.md`.

#### Anchor batch public-witness lane (W2.3)

W2.3 promotes the executable subset of `claim.anchor.batch_continuity` from
proposed to enforced and ships the production wiring that backs it. Rekor
Merkle inclusion-proof checking and formal anti-equivocation theorem coverage
remain proposed evidence until implemented. The relevant artifacts live under
`crates/economy/chio-anchor/src/witness*`:

- `AnchorWitnessClient`: an `async_trait` with `publish(&AnchorBatch)` and
  `verify_inclusion(&WitnessReceipt)`.
- `RekorClient`: real Sigstore Rekor REST client. `publish` POSTs the
  canonical-JSON encoding of `body` to `/api/v1/log/entries` with a Sigstore
  intoto envelope keyed by `sha256(canonical_jcs(body))`. `verify_inclusion`
  GETs `/api/v1/log/entries/<uuid>` and asserts the returned
  `body.spec.content.hash.value` equals the receipt's `body_hash` and verifies
  the Rekor signed-entry timestamp against the configured trusted key set. It
  does not yet verify Rekor's Merkle inclusion path to a checkpoint. Mismatches,
  HTTP non-2xx, network failures, invalid signed-entry timestamps, and entries
  past `max_witness_age_seconds` are reported as fail-closed errors.
- `OtsClient`: OpenTimestamps client. `publish` POSTs `body_hash` to
  `<calendar>/digest` and parses the returned timestamp through the
  `opentimestamps` crate, but OTS is advisory for the W2.3 public-witness
  requirement. A local parse plus a Bitcoin attestation marker is self-assertable
  without trusted Bitcoin block-header evidence or independently verified
  calendar commitment evidence, so `verify_inclusion` fails closed and OTS
  receipts do not satisfy `require_public_witness`.

`batch_body_hash` is `sha256(canonical_jcs(BatchHashInput))`, where
`BatchHashInput` contains `schema`, `treeRoot`, `checkpointIds`, `inclusions`,
`issuedAt`, `signerKey`, and a stable witness projection with only `kind` and
`root`. It explicitly excludes `witnessState`, lane-assigned `witnessId`, and
lane observation timestamps. This keeps the hash stable when a lane returns a
UUID or when the producer re-signs the batch with an embedded `WitnessReceipt`.
Verifiers separately require `receipt.kind == body.witness.kind`,
`receipt.witness_root == body.tree_root`, and
`receipt.body_hash == batch_body_hash(batch)`.

Each batch carries a `WitnessState` lifecycle:

- `Pending`: minted locally, no lane has confirmed yet.
- `Witnessed { receipt, observed_at }`: a successful publish or verify ran
  through `AnchorWitnessClient`. `receipt.witness_root == body.tree_root`
  is invariant and re-checked on every verify.
- `Stale { last_verified, error }`: the producer reports that the lane was
  reachable in the past but re-verification failed. The verifier treats
  `last_verified` as telemetry only. The verifier rule is:
  - `require_public_witness: true`, `Pending` -> reject.
  - `require_public_witness: true`, `Witnessed` on the sync path -> reject;
    use the async verifier path so `AnchorWitnessClient::verify_inclusion`
    runs.
  - `require_public_witness: true`, `Stale` and no verifier-owned cache entry
    for the recomputed `batch_body_hash` -> reject.
  - `require_public_witness: true`, `Stale` and
    `now - cache.verified_at > stale_window_seconds` -> reject.
  - `require_public_witness: true`, `Stale` inside the verifier-owned cache
    window -> accept (the receipt is still authoritative for already-witnessed
    batches).
  - `require_public_witness: false` -> accept all states (advisory mode).

Producers and consumers MUST route load-bearing public-witness verification
through `verify_anchor_batch_with_witness_policy_async` whenever
`require_public_witness=true`. The synchronous entry point
`verify_anchor_batch_with_witness_policy` MUST reject any policy carrying
`require_public_witness=true` at runtime, before structural verification,
regardless of `WitnessState`. The synchronous wrapper is reserved for
advisory-mode callers (`require_public_witness=false`) that intentionally
treat witness state as non-binding. This is a tightening of the per-state
arrow rules above: making the routing rule load-bearing decouples it from
the per-state table so a future state addition cannot accidentally re-open
the bypass. The runtime gate at
`crates/economy/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy`
returning `AnchorError::SyncRouteRequiresAdvisoryPolicy` is the load-bearing
enforcement; the companion `scripts/check-anchor-batch-async-witness.sh`
lint is best-effort fast feedback only and does not provide a soundness
guarantee.

Rejection criteria the W2.3 negative-conformance suite exercises:

- forged Merkle root (real Merkle re-compute, not a label compare): rebuilding
  the tree from `body.checkpoint_ids` and asserting `tree.root() ==
  body.tree_root` plus walking each inclusion proof through `verify_hash`.
- mis-ordered audit path: reversing or swapping siblings on a non-trivial
  audit path while keeping leaf hashes consistent. Detected only by real
  Merkle math.
- witness-lane impersonation: the lane returns an entry whose
  `body.spec.content.hash.value` does not match the batch's body hash, OR the
  lane returns an entry under a different UUID. Both cases fail closed.
- stale-witness fallback: dropping the lane while the policy is
  `require_public_witness=true` rejects new pending batches but keeps
  already-witnessed receipts usable inside the configured stale window only
  when the verifier's own cache has a fresh `verified_at` timestamp for the
  batch body hash.
- OTS marker-only witness receipts: an OTS proof that decodes, matches the batch
  body hash, and contains a Bitcoin attestation marker is still rejected under
  `require_public_witness` until trusted Bitcoin header or calendar-backed
  commitment evidence is present in the receipt contract.

The negative tests live as standalone files at
`crates/tooling/chio-conformance/tests/anchor_batch_{forged_root,misordered_proof,witness_impersonation,stale_witness_fallback}_rejected.rs`
(plus `anchor_batch_stale_witness_fallback.rs`) and exercise the real
`verify_anchor_batch` and `verify_anchor_batch_with_witness_policy` paths.

### 6.6 HTTP Receipts

The HTTP substrate (see [HTTP-SUBSTRATE.md](HTTP-SUBSTRATE.md)) introduces
`HttpReceipt`, a domain-specific receipt type for HTTP-layer policy evaluations.
`HttpReceipt` captures HTTP-specific context that `ChioReceipt` does not natively
model, including the evaluated HTTP method, path, query parameters, request
headers, caller identity, authentication method, and the sidecar verdict.

`HttpReceipt` is the receipt format returned by the sidecar evaluation endpoint.
`ChioReceipt` remains the unified storage and verification format for all Chio
receipt workflows, including checkpoints, evidence export, and federation.

The deterministic mapping from `HttpReceipt` to `ChioReceipt` is defined in
[HTTP-SUBSTRATE.md Section 5](HTTP-SUBSTRATE.md). That mapping preserves:

- `receipt_id` as the stable identifier across both formats
- `tool_server` derived from the OpenAPI server identity or sidecar
  configuration
- `tool_name` derived from the matched `operationId`
- `decision` mapped from the sidecar verdict
- HTTP-specific evaluation context projected into `ChioReceipt.metadata`
- `policy_hash` and `content_hash` carried through unchanged

This mapping is deterministic: the same `HttpReceipt` always produces the same
`ChioReceipt`. Operators may store either or both formats, but checkpoint
signing and evidence export always operate on the `ChioReceipt` representation.

## 7. Manifest Contract

Tool discovery currently uses the frozen manifest schema:

```text
chio.manifest.v1
```

The manifest defines:

- server identity
- one or more tool definitions
- per-tool input and optional output schemas
- operator-facing descriptions and metadata

This manifest is the authoritative discovery contract for native tool servers
and for mediated adapters that synthesize a Chio tool surface from another
protocol. `chio.manifest.v1` remains frozen in this release for compatibility.

### 7.1 OpenAPI-Derived Manifests

Chio includes an automated pipeline for deriving `chio.manifest.v1` tool
definitions from OpenAPI 3.0.x and 3.1.x specifications. Each HTTP operation
(method + path pair) in the OpenAPI spec becomes one `ToolDefinition`. The full
pipeline is specified in [OPENAPI-INTEGRATION.md](OPENAPI-INTEGRATION.md).

The `x-chio-*` extension vocabulary provides the policy overlay for OpenAPI
specs. Extensions may appear at the operation, path, or root level and control:

- `x-chio-scope`: capability scope required for the operation
- `x-chio-guard`: guard expressions evaluated during policy admission
- `x-chio-rate-limit`: per-operation rate constraints
- `x-chio-require-auth`: authentication requirements beyond the OpenAPI
  `securitySchemes`

When no `x-chio-*` extensions are present, the pipeline applies a default
deny-by-method policy that assigns conservative scope requirements based on
the HTTP method. This ensures fail-closed behavior for undecorated specs.

The derived `chio.manifest.v1` output is identical in structure to hand-authored
manifests. Downstream consumers (the kernel, trust-control, and receipt
pipeline) do not distinguish between hand-authored and OpenAPI-derived
manifests.

## 8. Runtime Surfaces

### 8.1 Local CLI And Kernel

The repository ships these primary runtime entrypoints:

- `chio check` -- single-call policy evaluation in preflight mode, or full mode with an explicit output fixture for post-output guards
- `chio run`
- `chio mcp serve`
- `chio mcp serve-http`
- `chio trust serve`
- `chio receipt explain`
- `chio proof serve` -- static Proof Room server over a collected and verified proof bundle (section 8.5)
- `chio api protect` -- reverse proxy that enforces Chio policy over an HTTP API using an OpenAPI spec
- `chio cert generate` -- generate TLS or signing certificates for Chio operator use
- `chio cert verify` -- verify a certificate chain or signing material against Chio trust roots
- `chio cert inspect` -- display certificate metadata, expiry, and key bindings

These surfaces intentionally share the same core receipt, capability,
revocation, and policy primitives rather than defining separate trust models.

`chio receipt explain <receipt-id>` loads the content-addressed receipt from
the local receipt DB or control plane. It renders the signed decision, policy
hash, guard evidence, parent receipt set, batch witness reference when present,
and a repair hint for denials or incomplete receipts. It is a local CLI
narrator, not a replacement for signature verification.

### 8.2 MCP Compatibility

Chio does not claim to replace MCP. It ships an MCP-compatible mediation layer
that currently covers:

- tools
- resources
- prompts
- completions
- logging
- tasks
- progress notifications
- nested sampling, elicitation, and roots callbacks
- remote HTTP auth discovery. Hosted OAuth authorization-server product work is
  explicitly blocked until the OAuth AS ADR or equivalent decision note is
  accepted.

Compatibility claims are grounded in checked-in conformance scenarios, live JS
and Python peers, and the release-qualification wave corpus.

### 8.3 Hosted Remote Admin

`chio mcp serve-http` ships operator-facing admin APIs, including:

- `/admin/health`
- `/admin/authority`
- `/admin/sessions`
- `/admin/sessions/{session_id}/trust`
- `/admin/receipts/...`
- `/admin/revocations`
- `/admin/budgets`

These surfaces are part of the supported production-diagnostics contract for
the hosted edge.

### 8.4 HTTP egress contract enforcement (W2.2)

Every kernel, guard, and adapter outbound HTTP path declares a typed
`HttpEgressContract` and routes its dispatch through
`chio_egress_contract::send_with_contract` (or, for non-reqwest substrates,
through the URL-only `enforce_url` and `enforce_response_bytes` helpers)
before any byte leaves the substrate. The contract carries:

- a tenant-scoped namespace,
- a lowercase scheme allow-list,
- an exact authority allow-list,
- explicit denials for loopback, IPv4/IPv6 link-local, and IPv6 unique-local
  (`fc00::/7`),
- a `max_redirect_chain` ceiling that bounds redirect hop count, and
- a `max_response_bytes` ceiling that bounds the observed response body.

Reject scenarios (each surfaced as a structured `HttpEgressError`):

- loopback target rejected (`LoopbackDenied`),
- link-local / cloud metadata target rejected (`LinkLocalDenied`),
- IPv6 ULA target rejected (`Ipv6UlaDenied`),
- redirect chain exceeds the contract ceiling (`RedirectLimitExceeded`),
- response body exceeds the contract ceiling (`ResponseTooLarge`),
- scheme outside the allow-list (`SchemeDenied`),
- authority outside the allow-list (`AuthorityDenied`).

The W2.2 rollout wires this contract into every shipped substrate caller
in `chio-link` (Chainlink, Pyth, sequencer), `chio-siem` (webhook, Splunk,
Elasticsearch, Sumo Logic, Datadog, OCSF, alerting backends), the
`chio-a2a-adapter` ureq dispatch helpers, the `chio-openapi-mcp-bridge`
dispatcher invocation, and the `chio-mcp-remote` introspection-bearer
verifier. Two public-settlement verifier surfaces added after the initial
rollout also belong to this inventory: the `chio-cli` proof verifier's
independent-chain JSON-RPC caller
(`crates/products/chio-cli/src/cli/dispatch/proof/env.rs`) and the Proof
Room upload verifier's equivalent caller
(`crates/products/chio-proof-room/src/lib.rs`). Both derive a
single-authority `HttpEgressContract` from
`CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL` (tenant namespace
`proof.public-settlement.rpc`, redirects disabled, `max_redirect_chain` of
zero, `max_response_bytes` of 1 MiB) and enforce it on every JSON-RPC call.
A workspace lint at `scripts/check-http-egress-contract.sh`
catches regressions; a self-test at
`scripts/tests/check-http-egress-contract.test.sh` proves the lint accepts
wired callers and rejects bare reqwest dispatch. Five standalone SSRF
negative-conformance tests in `crates/tooling/chio-conformance/tests/ssrf_*.rs`
exercise the failure paths through real production callers.

These two public-settlement RPC callers use
`client_builder_with_contract` and `send_with_contract`, so DNS resolution,
connect target binding, redirect denial, and streaming response byte ceilings
are enforced by the shared helper instead of by a direct-reqwest
classification marker.

For reqwest-based callers that cannot route dispatch through
`send_with_contract`, the lint defines a second sanctioned enforcement mode:
the `CHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST:` classification marker. A comment
carrying that marker on, or within four lines above, a flagged client
construction or dispatch line classifies the site, and the lint accepts it.
The marker is a classification, not an exemption: a classified caller MUST
still enforce the contract manually. Concretely, it MUST run `enforce_url`
(or `enforce_url_with_dns`) against the target URL before dispatch, MUST
disable automatic HTTP-client redirects so the `max_redirect_chain` ceiling
cannot be bypassed inside the client, and MUST run `enforce_response_bytes`
against the declared `Content-Length` when present and against the buffered
response body before parsing it. Caveat: because these callers buffer the
response before the byte-cap check, `max_response_bytes` bounds what a
classified caller accepts, not what the transport transfers; a peer that
omits or understates `Content-Length` can still cause the full oversized
body to be read into memory before rejection. Unmarked direct reqwest
dispatch remains a lint failure.

### 8.5 Proof Room

`chio proof serve` serves a static, read-only Proof Room over a collected
proof bundle. The router
(`crates/products/chio-proof-room/src/server.rs`) exposes `/` (a redirect
into the Proof Room UI view), `/manifest.json`, `/artifacts/*`,
`/negatives/*`, `/roots/*`, `/ui/*`, and `/verifier/*`, plus the fixture
catalog, trusted-bundle-signer, fixture-asset, and upload-verification
endpoints. Served bundle paths are pinned to the manifest's declared
artifact set; requests outside that set are rejected rather than resolved
against the filesystem.

The Proof Room artifact family is defined by the eleven schemas in
`spec/schemas/chio-proof-room/v1/`. The three load-bearing artifact kinds
are:

- Bundle (`chio.proof-room.bundle.v1`, `bundle.schema.json`): the signed
  bundle manifest. It binds a bundle id, fixture id, stage, source commit,
  branch, and command, the Chio version and schema-version inventory, the
  transaction-passport and evidence-graph references, the source and Proof
  Room verifier-report references, the served artifact list, rendered
  claims, a receipt-coverage matrix, explicit negative cases, advisory and
  excluded artifact declarations, and a detached DSSE signature
  (payload type `application/vnd.chio.proof-room.bundle.v1+json`). All of
  those fields are required, and unknown schema identifiers are rejected.
- Verifier report (`chio.proof-room.verifier-report.v1`,
  `verifier-report.schema.json`): the Proof-Room-level verdict over one
  bundle. It records the verdict, bundle and fixture ids, a reference to
  the source verifier report it projects, the UI verdict source, and the
  rendered claims. It is a presentation-plane projection: the source
  verifier report and the signed receipts underneath remain the
  authoritative truth, and a Proof Room verdict MUST NOT be treated as
  stronger than the verified bundle signature, pinned trusted signer keys,
  and underlying signed evidence it binds.
- Fixture catalog (`chio.proof-room.fixture-catalog.v1`,
  `fixture-catalog.schema.json`, plus
  `chio.proof-room.fixture-root-catalog.v1`): the enumeration of fixture
  bundles a Proof Room instance may serve. Catalog entries are advisory
  discovery data; listing a fixture does not verify it.

The remaining schemas type the evidence payloads a bundle may carry:
`chio.proof-room.receipt-evidence.v1`,
`chio.proof.docker-quickstart-evidence.v1`, `chio.proof.release-truth.v1`,
and the `chio.proof.first-run.*.v1` capability-proof, guard-report,
trust-roots, and command-log family.

Proof Room semantics are fail-closed and presentation-scoped. Serving,
listing, or rendering Proof Room artifacts creates no authorization and
does not widen signed Chio truth or capability scope. The upload-verify
endpoint re-verifies a submitted bundle against pinned trusted signer keys
and the schema set above before reporting a verdict; verification failures
deny.

## 9. Trust-Control Contract

`chio trust serve` is the shipped trust-control HTTP service.

Core operator and cluster surfaces include:

- `/health`
- `/v1/authority`
- `/v1/capabilities/issue`
- `/v1/internal/cluster/status`
- `/v1/receipts/query`
- `/v1/reports/operator`
- `/v1/reports/behavioral-feed`
- `/v1/reports/underwriting-input`
- `/v1/reports/exposure-ledger`
- `/v1/reports/credit-scorecard`
- `/v1/reports/settlements`
- `/v1/reports/economic-receipts`
- `/v1/reports/economic-completion-flow`
- `/v1/reports/authorization-context`
- `/v1/reports/authorization-profile-metadata`
- `/v1/reports/authorization-review-pack`
- `/v1/settlements/reconcile`
- `/v1/federation/evidence-shares`
- `/v1/reputation/compare/{subject_key}`
- `/v1/reputation/portable/summaries/issue`
- `/v1/reputation/portable/events/issue`
- `/v1/reputation/portable/evaluate`

Federation and certification administration includes:

- `/v1/federation/providers`
- `/v1/federation/providers/{provider_id}`
- `/v1/certifications`
- `/v1/certifications/{artifact_id}`
- `/v1/certifications/resolve/{tool_server_id}`
- `/v1/certifications/discovery/publish`
- `/v1/certifications/discovery/resolve/{tool_server_id}`
- `/v1/certifications/discovery/search`
- `/v1/certifications/discovery/transparency`
- `/v1/certifications/discovery/consume`
- `/v1/certifications/{artifact_id}/revoke`
- `/v1/certifications/{artifact_id}/dispute`
- `/v1/public/certifications/metadata`
- `/v1/public/certifications/resolve/{tool_server_id}`
- `/v1/public/certifications/search`
- `/v1/public/certifications/transparency`

The health contract is additive JSON and currently includes authority, store,
federation, and cluster summaries rather than a single opaque boolean.
`/v1/reports/operator` now also carries settlement backlog visibility and
explicit multi-dimensional budget profiles. Budget utilization rows expose
named `dimensions.invocations` and `dimensions.money` usage blocks, while
settlement backlog rows pair signed `financial.settlement_status` with mutable
sidecar reconciliation state keyed by `receipt_id`.

Cluster snapshots that carry immutable pre-upgrade budget usage anchors MUST
also carry `chio.budget-snapshot-anchor-provenance.v1`. The provenance binds the
canonical anchor-set digest into an append-only authority commitment chain,
signs every chain entry with the serving leader's authority key, and
authenticates the complete inclusion chain with the configured cluster service
trust root. A follower MUST accept a previously absent wire anchor only from its
locally elected leader, at the exact local election term, after verifying the
chain from its genesis digest and preserving any previously accepted head.
Ordinary snapshot imports remain unable to create migration anchors.
`/v1/reports/metered-billing` and `/v1/metered-billing/reconcile` apply the
same pattern to post-execution metered-cost evidence for governed
non-payment-rail tools.
`/v1/reports/economic-receipts` projects one receipt-scoped economic envelope
alongside mutable settlement and metering reconciliation state, while
`/v1/reports/economic-completion-flow` bundles that receipt truth with the
persisted underwriting, credit-facility, and credit-bond surfaces over one
shared bounded query.
`/v1/reports/authorization-context` exports a standards-legible projection of
governed receipts into:

- one or more derived `authorization_details` rows describing the governed
  tool action plus any explicit commerce or metered-billing scope
- a separate `transaction_context` block carrying the signed `intent_id`,
  `intent_hash`, approval token identifiers, runtime-assurance context,
  optional delegated `call_chain` provenance envelope, and one optional
  `identity_assertion` continuity envelope

That projection is always derived from the signed governed receipt metadata.
Trust-control does not accept a second independently editable authorization
document, because that would silently widen authority or billing scope outside
the approval-bound intent hash. If delegated `call_chain` context is present in
that projection, it must preserve the provenance evidence class and may only be
treated as sender-bound truth when backed by observed local lineage, a signed
receipt-lineage statement, or a verified continuation token scoped by the
relevant session anchor.

The report now declares Chio's first normative enterprise-facing profile over
that projection:

- report `schema`: `chio.oauth.authorization-context-report.v1`
- profile `schema`: `chio.oauth.authorization-profile.v1`
- profile `id`: `chio-governed-rar-v1`

This profile is intentionally narrow. Chio claims one RFC-9396-style
authorization-details mapping over governed receipt truth plus a separate
transaction-context block carrying the approval-bound intent hash, approval
evidence, runtime-assurance posture, delegated call-chain context, and one
optional identity assertion continuity object. If a governed receipt cannot be
projected into that profile truthfully, Chio fails closed and does not emit a
partial authorization-context report.

Each authorization-context row now also carries explicit sender-bound
semantics:

- `senderConstraint.subjectKey`
- `senderConstraint.subjectKeySource`
- `senderConstraint.matchedGrantIndex`
- `senderConstraint.proofRequired`
- optional `senderConstraint.proofType`
- optional `senderConstraint.proofSchema`
- `senderConstraint.runtimeAssuranceBound`
- `senderConstraint.delegatedCallChainBound`

Chio resolves that sender truth from receipt attribution plus persisted
capability lineage. If the capability snapshot is missing, the grant cannot be
resolved, the subject binding is inconsistent, or a required DPoP proof shape
cannot be represented, the report fails closed instead of degrading silently.
These reports describe bounded runtime truth; they do not transform asserted
delegated call-chain fields into independently verified upstream provenance,
and `senderConstraint.delegatedCallChainBound` is reserved for observed or
verified lineage only.

Chio does not claim OAuth authorization-server product status in this v1
contract. The bounded OAuth authorization profile below is an accepted
planning boundary for the feature-gated authorization edge, not a generally
available product surface, and remains blocked for product use until a
dedicated OAuth AS ADR or equivalent decision note is accepted. When enabled in
local or operator-gated builds, the draft `chio_authorization_profile` includes:

- one request-time contract naming `authorization_details` and
  `chio_transaction_context` as the only supported Chio request parameters and
  access-token claims
- one resource-binding contract requiring the OAuth `resource` parameter to
  match the protected-resource metadata and requiring bearer admission to match
  the same protected resource through `aud`, `resource`, or both
- one artifact-boundary contract stating that access tokens are runtime
  authorization artifacts while approval tokens, Chio capabilities, and review
  evidence remain non-bearer artifacts

In that gated path, Chio only accepts the bounded governed detail family
`chio_governed_tool`, `chio_governed_commerce`, and
`chio_governed_metered_billing`, and at least one governed-tool row must be
present. Malformed transaction context, unsupported detail types, mismatched
resource indicators, stale identity assertions, mismatched verifier bindings,
request-binding mismatches, or ambiguous approval/runtime-assurance/call-chain
fragments fail closed before token issuance.

The same gated path sketches one bounded sender-constrained continuation
contract. The request may carry:

- `chio_sender_dpop_public_key`
- `chio_sender_mtls_thumbprint_sha256`
- `chio_sender_attestation_sha256`

If that gated path approves the request, the resulting sender constraint is
persisted on the authorization code and then projected into access tokens
through `cnf`:

- `cnf.chioSenderKey`
- `cnf["x5t#S256"]`
- `cnf.chioAttestationSha256`

Runtime admission for the gated path then enforces the same bound sender proof
continuity:

- DPoP-bound flows must present a valid proof during token exchange and again
  on protected-resource admission, including nonce, `jti`, `htm`, and `htu`
  checks over the actual runtime request
- mTLS-bound flows must present a matching
  `x-chio-mtls-thumbprint-sha256` header
- attestation-bound flows must present a matching
  `x-chio-runtime-attestation-sha256` header, and that digest must also match
  `chio_transaction_context.runtimeAssuranceEvidenceSha256`

Attestation alone never authorizes a sender. Chio only accepts the
attestation-bound profile when it is paired with DPoP or mTLS continuity over
the same request. Missing, stale, replayed, or mismatched sender proof fails
closed as `invalid_request`, `invalid_grant`, or bearer denial depending on
where the mismatch occurs.

When the gated path is configured, the hosted edge may publish the same profile
through OAuth-family discovery documents:

- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-authorization-server/{issuer-path}`

Both documents include `chio_authorization_profile`, which mirrors the
canonical profile id/schema, sender-constraint expectations, request-time
parameter names, resource-binding rules, and artifact-boundary expectations.
Discovery is informational only. Chio does not widen trust from discovery
documents alone, and the edge fails closed if protected-resource and
authorization-server metadata disagree about the advertised Chio profile or
authorization-server issuer.

`/v1/reports/authorization-profile-metadata` packages that same profile into a
machine-readable artifact for enterprise review. The report publishes:

- metadata `schema`: `chio.oauth.authorization-metadata.v1`
- canonical Chio profile `id` and `schema`
- the authorization-context report schema
- supported discovery paths
- explicit support boundaries
- example field mappings for authorization details, transaction context, and
  sender constraints
- request-time contract, resource-binding, and runtime-versus-audit artifact
  boundaries

`/v1/reports/authorization-review-pack` packages a reviewer-facing evidence
bundle over the same filter surface as `/v1/reports/authorization-context`.
Each returned record includes:

- the derived `authorization_context` row
- the typed `governed_transaction` metadata block
- the full signed `ChioReceipt`

This pack exists so enterprise IAM reviewers can trace one governed action from
approval-bound intent through standards-legible projection back to canonical
receipt truth without bespoke Chio-specific joins.

Chio also validates assurance-bound and delegated-call-chain projection
integrity fail closed. If a row claims runtime assurance, the projection must
also carry the accepted schema, verifier family, verifier, and evidence
digest. If a row claims delegated call-chain context, the projection must
carry non-empty `chainId`, `parentRequestId`, `originSubject`, and
`delegatorSubject` values, plus a non-empty `parentReceiptId` when present.
Chio does not emit partial or degraded enterprise-profile rows when that
projection cannot be represented truthfully.

`/v1/capabilities/issue` accepts the same typed capability-issuance contract
used by the local CLI path, including optional `runtimeAttestation` evidence.
When trust-control is started with a policy containing
`extensions.runtime_assurance`, issuance resolves the highest satisfied runtime
assurance tier, enforces that tier's scope ceiling, and marks economically
sensitive grants with an explicit minimum runtime-assurance constraint for
later governed execution. `/health` also reports whether this runtime
assurance issuance policy is configured.

When the same policy also defines
`extensions.runtime_assurance.trusted_verifiers`, issuance and governed
execution treat runtime attestation as explicit trusted evidence rather than
opaque metadata. Each trusted-verifier rule binds one `{schema, verifier}`
pairs to an effective runtime-assurance tier plus optional verifier-family,
maximum evidence age, attestation-type, and required-assertion constraints. If
trusted-verifier rules are configured, carried attestation evidence must match
one rule and satisfy its freshness and claim constraints or the request fails
closed. If no
trusted-verifier rules are configured, Chio continues to use the normalized raw
attestation tier after validating evidence time bounds and workload-identity
binding.

When `runtimeAttestation` carries workload identity, Chio currently recognizes
one normalized mapping shape:

- explicit `workloadIdentity { scheme, credentialKind, uri, trustDomain, path }`
- `scheme: spiffe`
- `credentialKind: uri | x509_svid | jwt_svid`

If only the raw `runtimeIdentity` compatibility field is present and it is a valid
SPIFFE URI, Chio derives the same normalized mapping for policy, governed
validation, and receipt metadata. If `runtimeIdentity` is non-SPIFFE, Chio
preserves it as opaque verifier metadata and does not invent a typed identity
projection. If an explicit `workloadIdentity` conflicts with `runtimeIdentity`,
or if a claimed SPIFFE identifier is malformed, issuance and governed
execution fail closed.

Chio's first concrete verifier bridge is Azure Attestation JWT normalization.
That bridge verifies a signed Azure MAA token against operator-supplied or
metadata-resolved RSA signing material, preserves vendor claims under
`claims.azureMaa`, optionally projects one configured
`x-ms-runtime.claims.*` SPIFFE URI through the same workload-identity mapping
rules above, and normalizes the raw verifier output to `attested`. That raw
output can only rebind to `verified` or another effective runtime tier through
explicit `trusted_verifiers` policy.

Chio's second concrete verifier bridge is AWS Nitro attestation document
verification. That bridge verifies an AWS Nitro `COSE_Sign1` document with
`ES384`, validates certificate anchoring against operator-configured trusted
roots, enforces `SHA384` PCR expectations, freshness, optional nonce matching,
and debug-mode denial by default, preserves vendor claims under
`claims.awsNitro`, and likewise normalizes the raw verifier output to
`attested` until later trust policy rebinding says otherwise.

Chio's third concrete verifier bridge is Google Confidential VM JWT
normalization. That bridge verifies a signed Google attestation token against
metadata-resolved `JWKS` material, enforces issuer, audience, hardware-model,
and secure-boot constraints, preserves vendor claims under
`claims.googleAttestation`, and also keeps the raw normalized verifier output
at `attested` until explicit `trusted_verifiers` policy rebinds it higher.

Verifier adapters now also emit a canonical runtime-attestation appraisal
artifact over the same evidence. The appraisal contract separates:

- evidence identity (`schema`, `verifier`, time bounds, evidence digest)
- verifier-family and adapter identity
- normalized assertions Chio is willing to compare across verifier families
- vendor-scoped claims preserved without claiming cross-vendor equivalence
- explicit reason codes and the effective runtime tier carried forward

In the outward-facing artifact shape, those layers are now explicit nested
components:

- `evidence` for raw evidence identity and freshness metadata
- `verifier` for adapter and verifier-family identity
- `claims` for normalized Chio-visible assertions, structured normalized claim
  descriptors, and preserved vendor-scoped claims
- `policy` for verdict, carried-forward effective tier, reason codes, and the
  corresponding structured reason descriptors

Chio's normalized claim vocabulary is now explicit and versioned. The current
portable claim catalog covers:

- `attestation_type`
- `runtime_identity`
- `workload_identity_scheme`
- `workload_identity_uri`
- `module_id`
- `measurement_digest`
- `measurement_registers`
- `hardware_model`
- `secure_boot_state`

Each structured normalized claim carries:

- portable claim `code`
- compatibility `legacyAssertionKey`
- claim `category`
- claim `confidence`
- claim `freshness`
- claim `provenance`
- normalized `value`

Chio's reason taxonomy is also explicit and versioned. Structured reasons carry:

- reason `code`
- reason `group`
- reason `disposition`
- human-readable `description`

The current shared reason taxonomy includes pass, warn, deny, degrade, and
unknown dispositions over verification, compatibility, freshness,
measurement, debug-posture, and policy groups. Chio preserves the flat
`reasonCodes` array for compatibility, but the structured reason objects are
the portable contract going forward.

Chio also carries one migration inventory over the current concrete bridges. At
this stage that inventory is fixed to Azure MAA, AWS Nitro, Google
Confidential VM, and Chio's signed `enterprise_verifier` family, and it makes
the vendor claim namespace plus normalized key set, normalized claim codes,
and default reason codes explicit for each bridge without claiming generic
cross-vendor standardization.

Chio treats that appraisal contract as the stable adapter boundary. New
verifier families must project into the same appraisal shape instead of
inventing new policy-specific blobs.

Chio now also externalizes one signed appraisal-result contract over that same
artifact boundary. The signed result carries:

- result `schema`: `chio.runtime-attestation.appraisal-result.v1`
- deterministic `resultId`
- `exportedAt`
- exporting `issuer`
- nested `appraisal` artifact
- exporting `exporterPolicyOutcome`
- explicit `subject` provenance over `runtimeIdentity` and optional
  `workloadIdentity`

The signed envelope authenticates the result body with the exporter's signing
key, but that signature does not itself widen local trust. Imported appraisal
results must still pass one explicit local import policy. Chio's import-policy
surface carries:

- trusted `issuer` identifiers
- trusted signer-key fingerprints
- allowed verifier families
- maximum result age
- maximum evidence age
- optional local maximum effective tier
- required portable normalized-claim values

Import evaluation yields one structured local outcome with disposition
`allow`, `attenuate`, or `reject`. Chio rejects fail closed when:

- no explicit local import policy is present
- the signed result fails signature verification
- the result or nested artifact schema is unsupported
- the evidence schema and declared verifier family do not match Chio's bounded
  appraisal bridge inventory
- the result is stale
- the underlying evidence is stale
- the exporter itself rejected the appraisal
- the issuer or signer is not explicitly trusted
- the verifier family is outside local policy
- a required portable claim is missing or mismatched

If the imported result is otherwise acceptable but exceeds the locally allowed
effective runtime-assurance tier, Chio attenuates the tier explicitly instead
of rejecting the result silently or widening local authority.

Chio now locally qualifies that appraisal-result boundary across the shipped
Azure MAA, AWS Nitro, Google Confidential VM, and bounded
`enterprise_verifier` bridges. The qualified negative paths include stale
results, stale evidence, unsupported verifier-family policy, and contradictory
portable claims. Chio does not currently claim one-time consume or
replay-registry semantics for imported results; the current replay defense at
this boundary is explicit signature plus freshness validation.

Chio now also defines one bounded verifier-federation metadata layer over that
same appraisal boundary. The portable artifacts are:

- signed verifier descriptor
  `chio.runtime-attestation.verifier-descriptor.v1`
- signed reference-value set
  `chio.runtime-attestation.reference-values.v1`
- signed trust bundle
  `chio.runtime-attestation.trust-bundle.v1`

The signed verifier descriptor makes verifier identity machine-readable
without collapsing it into local policy. The descriptor carries:

- stable `descriptorId`
- verifier `verifier` identifier
- verifier `verifierFamily`
- concrete Chio adapter `adapter`
- bounded compatible `attestationSchemas`
- canonical `appraisalArtifactSchema`
- canonical `appraisalResultSchema`
- trusted signer-key fingerprints for that verifier
- optional `referenceValuesUri`
- explicit `issuedAt` and `expiresAt`

Signed reference-value sets distribute one verifier-family and one
attestation-schema-specific measurement package without hiding freshness or
replacement state. Each set carries:

- stable `referenceValueId`
- bound `descriptorId`
- verifier `verifierFamily`
- compatible `attestationSchema`
- optional source URI
- explicit issuance and expiry
- lifecycle state `active`, `superseded`, or `revoked`
- explicit `supersededBy` only for superseded sets
- explicit `revokedReason` only for revoked sets
- one non-empty measurement map

The signed trust bundle is the portable distribution artifact. It carries:

- stable `bundleId`
- publishing `publisher`
- explicit integer `version`
- explicit issuance and expiry
- one bounded set of signed verifier descriptors
- one bounded set of signed reference-value sets

Chio fails closed when trust-bundle material is stale, not yet valid, unsigned,
partially signed, internally contradictory, or outside the declared verifier
contract. The fail-closed conditions include:

- duplicate descriptor ids or duplicate reference-value ids
- reference-value sets that point to an unknown descriptor
- verifier-family mismatch between a descriptor and a reference-value set
- attestation-schema mismatch between a descriptor and a reference-value set
- ambiguous active reference values for one `{descriptorId, attestationSchema}`
  slot
- superseded reference-value sets that do not name an existing successor

These bundle artifacts do not themselves widen local trust. They make verifier
identity, signer material, and reference values portable and signed, but
operators must still decide explicitly how or whether those artifacts inform
local trust admission.

When Chio emits governed receipt metadata or underwriting evidence derived from
trusted runtime attestation, it carries the accepted attestation `schema`,
optional `verifierFamily`, resolved effective tier, verifier identifier, and
evidence digest so downstream consumers can audit why a stronger trust posture
was available.

`POST /v1/reports/runtime-attestation-appraisal` is Chio's operator-facing
export surface for that same contract. It returns a signed appraisal report
containing:

- the canonical appraisal document over one carried runtime-attestation input
- one policy-visible outcome describing whether configured trusted-verifier
  rules accepted the evidence and which effective tier Chio resolved
- one immutable signature over the export body so operators and downstream
  reviewers can exchange the artifact without re-querying the live verifier

That report is intentionally narrower than a generic attestation-results or
EAT federation protocol. Chio claims one canonical appraisal contract plus
concrete Azure, AWS Nitro, and Google Confidential VM bridges, not universal
cross-vendor attestation interoperability.

`/v1/reports/behavioral-feed` is the insurer/risk export surface. It returns a
signed behavioral-feed document with:

- explicit filter scope (`capability_id`, `agent_subject`, tool filters,
  time window, receipt-detail limit)
- privacy/export boundary metadata derived from the canonical evidence-export
  contract
- separate decision, governed-action, settlement, and metered-billing
  reconciliation summaries
- optional subject reputation summary when the feed is scoped to one agent
- per-receipt detail rows carrying signed decision and governed metadata plus
  separate mutable metered-reconciliation state when applicable

The behavioral feed is a truthful evidence export, not an underwriting model.
It reuses canonical receipt, settlement, reputation, and shared-evidence state
instead of inventing a second telemetry pipeline.

`/v1/reports/underwriting-input` is the signed underwriting policy-input
surface. It reuses the same canonical receipt, reputation, certification,
runtime-assurance, settlement, metered-billing, and shared-evidence substrate
to emit:

- one explicit underwriting-query scope with required anchor filters and a
  bounded receipt-reference limit
- a stable `chio.underwriting.taxonomy.v1` vocabulary of risk classes and
  reason codes
- one canonical evidence snapshot covering receipt summaries plus optional
  reputation, certification, and runtime-assurance summaries
- derived risk signals that reference existing Chio evidence identifiers rather
  than inventing a second mutable telemetry stream

This underwriting-input artifact is a signed input contract, not yet a final
underwriting decision. It exists so later underwriting phases can evaluate one
typed, auditable evidence package instead of ad hoc partner JSON.

`/v1/reports/underwriting-decision` is the deterministic operator-facing
runtime underwriting surface. It evaluates the canonical underwriting-input
snapshot against Chio's default decision policy and returns:

- one bounded outcome in the vocabulary `approve`, `reduce_ceiling`,
  `step_up`, or `deny`
- one explicit decision-policy snapshot with receipt-history, reputation, and
  runtime-assurance thresholds
- explanation findings carrying normalized reason codes, optional originating
  underwriting-signal reasons, concrete receipt or reconciliation evidence
  references, and operator-remediation hints
- a suggested ceiling factor only when the bounded outcome is
  `reduce_ceiling`

This underwriting-decision report is intentionally separate from signed
receipts and from the signed underwriting-input snapshot. It is a deterministic
evaluation surface over canonical evidence, not the durable signed artifact
that operators later persist.

`POST /v1/underwriting/decisions/issue` signs and persists that durable
underwriting artifact. The signed decision envelope carries:

- one immutable decision artifact over the underwriting evaluation snapshot
- one explicit lifecycle and review state at issuance time
- one budget recommendation in the bounded vocabulary
  `preserve`/`reduce`/`hold`/`deny`
- one premium state in the bounded vocabulary
  `quoted`/`withheld`/`not_applicable`, plus basis points and a quoted amount
  when Chio can truthfully price exposure; mixed-currency governed exposure
  withholds the amount quote rather than comparing raw units across currencies
- one optional `supersedesDecisionId` reference that links a replacement
  decision without rewriting the original signed record

`GET /v1/reports/underwriting-decisions` lists persisted signed decisions plus
their current lifecycle projection and latest appeal status. The list/report
surface does not mutate or re-sign prior decisions: the original signed
artifact remains immutable, while the store projects current lifecycle state
such as `active` or `superseded`. Premium totals are partitioned by currency
in the report summary; the compatibility single total is populated only when the
matching quoted premiums share one currency.

`POST /v1/underwriting/appeals` and
`POST /v1/underwriting/appeals/resolve` manage explicit appeal records over
persisted underwriting decisions. Appeals may link to a replacement decision
only when the appeal is accepted, and they do not rewrite canonical execution
receipts or prior signed underwriting artifacts.

`POST /v1/reports/underwriting-simulation` is the non-mutating operator
simulation surface. It evaluates one operator-supplied underwriting policy
against the same canonical evidence snapshot used by the default runtime
evaluator and returns:

- the canonical underwriting-input evidence package used for the comparison
- the default Chio decision evaluation for that evidence
- the simulated decision evaluation for the supplied policy
- one explicit delta showing whether the outcome or risk class changed and
  which normalized reason labels were added or removed

The simulation surface does not persist or supersede any underwriting
decision. It exists so operators can inspect policy changes before or after
deployment without mutating signed decision artifacts.

`GET /v1/reports/exposure-ledger` is Chio's signed economic-position surface
over the same governed receipt, settlement, metered-billing, and persisted
underwriting-decision truth. It returns:

- one bounded query with required anchor filters and capped receipt/decision
  limits
- per-receipt position rows carrying governed ceiling, reserve, settlement,
  provisional-loss, and evidence-reference detail
- persisted underwriting decision rows so premium and supersession truth can
  be reviewed alongside receipt-side exposure
- per-currency aggregate positions covering governed maximum exposure,
  reserved, settled, pending, failed, provisional-loss, recovered, quoted
  premium, and active quoted-premium totals
- one explicit support-boundary block describing what Chio does and does not
  claim about the projected ledger

This ledger is intentionally narrower than a full claims or recovery system.
Chio does not currently claim cross-currency netting, claim-adjudication
closure, or finalized recovery lifecycle semantics in the signed export.
Mixed or contradictory row truth fails closed: if Chio cannot represent one
receipt row truthfully inside one currency position, it rejects the report
instead of fabricating a blended exposure row.

`GET /v1/reports/economic-completion-flow` is Chio's deterministic operator
bundle for reviewing one canonical `metering -> underwriting -> credit ->
settlement` path over persisted local artifacts. It returns:

- one normalized bounded query over receipt-side economic activity and
  decision-side underwriting or credit state
- one receipt-scoped economic projection report carrying signed economic
  authorization truth plus mutable settlement and metering reconciliation
- persisted underwriting decisions, credit facilities, and credit bonds over
  that same filter surface
- one summary that surfaces the latest underwriting, facility, and bond stage
  Chio can name truthfully without rewriting any underlying signed artifact

This bundle is intentionally narrower than finalized settlement provenance.
It shows one deterministic local completion view over persisted artifacts, but
it does not yet claim that every settlement row is bound to exactly one
completion-flow row. That stricter provenance claim remains downstream work.

`GET /v1/reports/credit-scorecard` is Chio's signed, subject-scoped credit
posture surface built from that same exposure ledger plus the canonical local
reputation inspection. It returns:

- one bounded subject-scoped query over exposure and persisted underwriting
  decision history
- one explicit weighted dimension model covering reputation support, settlement
  discipline, loss pressure, and exposure stewardship
- one bounded overall score, confidence level, and score band
- one explicit probation block carrying the receipt/day thresholds that kept
  the score in probationary posture
- one typed anomaly list with concrete evidence references back to receipts,
  settlement rows, underwriting-decision coverage, or reputation inspection

This scorecard is intentionally narrower than capital-allocation or facility
policy on its own. Missing subject scope or missing matching exposure fails
closed. Sparse history can still produce a scorecard, but only as explicit
low-confidence probationary posture rather than a confident facility-ready
decision.

`POST /v1/reputation/portable/summaries/issue`,
`POST /v1/reputation/portable/events/issue`, and
`POST /v1/reputation/portable/evaluate` are Chio's portable market-discipline
exchange surfaces. They sign one portable reputation-summary artifact and one
portable negative-event artifact over explicit issuer, subject, evidence, and
issuance or freshness state, then evaluate imported artifacts only through one
local weighting profile. Evaluation requires subject agreement, unique issuers,
allowed issuers, bounded freshness, non-contradictory summary or event timing,
and explicit attenuation or penalty settings. Unsupported, stale, future-dated,
duplicate, blocked, or contradictory inputs fail closed. This is portable
evidence, not a universal trust oracle, global trust score, or automatic
runtime-admission path.

Chio now also defines one bounded shared-clearing lane over those imported
artifacts through `chio.federation-reputation-clearing.v1`. That clearing
contract references one local weighting policy, one federated admission
policy, one bounded operator set, and one explicit anti-sybil policy. Accepted
positive reputation inputs must come from independent issuers, per-issuer input
count is capped, and blocking negative events require corroboration when the
policy says so. Shared clearing is still operator-local evaluation truth, not a
universal oracle or automatic runtime admission.

Chio runtime admission may consume pheromone concentration as evidence only
when a verifier-owned runtime policy explicitly enables it. The runtime policy,
peer weights, runtime trust input, and trusted verifier keys are local verifier
inputs. Request JSON may reference stable ids and hashes, but it cannot carry
trust roots or widen admission. Observe-only pheromone reports remain receipt
metadata and cannot change the verdict. Enforced policy can allow, deny, or
escalate before tool dispatch, but it does not issue leases, create governance
receipts, mutate trust, settle payments, or perform peer discovery.

Chio runtime proof-parity reports bind local admission output to structured
step evidence before claiming proof regeneration success. A runtime workflow
run report records per-step admission report hashes, tool receipt ids and
hashes, output hashes, bilateral DSSE hashes, workflow step hashes,
consistency anchors, destructive flags, and lease or governance ids where
present. Runtime proof regeneration now also emits a runtime evidence manifest,
a proof-regeneration input artifact, package-valid signed `ChioReceipt`
artifacts, strict Chio DSSE envelopes, a signed `WorkflowReceipt v2`,
`chio.attest.proof-package.v1`, verifier trust and context inputs, and the
verification report produced by the existing verification implementation. A
regeneration report may set `accepted=true` only when verification accepts the
regenerated package and the report binds proof package, verification report, and workflow
receipt hashes. `runtime_proof_semantic_regeneration_pending` is a rejected
gate state, not a successful runtime proof claim.

Chio production local runtime orchestration wraps the same runtime admission
and proof-regeneration evidence in verifier-owned local operating contracts.
An orchestration profile and run contract bind the local kernel id, verifier id,
expected workflow steps, admission ids, durable store id, evidence sink id, and
proof-regeneration requirement. The local orchestration store records runtime
bundles, consumed destructive leases, runtime trust floors, run states, step
states, and evidence artifact hashes. Operator status reports expose store
health, run counts, consumed leases, trust-floor heads, latest failure code,
evidence sink health, and ready/degraded state without widening admission
authority. Drift reports compare repeated verifier-accepted local proof outputs
by manifest closure, proof-regeneration reports, source records, verifier
report hashes, and stable semantic fields. Drift is operator evidence only; it
does not mutate policy, trust, leases, governance, settlement, pheromone state,
or provider routing.

Chio runtime operations hardening supervises local orchestration runs
without changing admission authority. A supervisor profile controls local run
lease TTLs, stale-run windows, evidence health requirements, static provider
binding checks, and dry-run retention posture. Scheduler tick reports claim
bounded pending runs with owner ids and fencing tokens; stale tokens cannot
write run state after takeover. Evidence sink health reports rehash required
artifacts and probe write plus atomic rename readiness. Recovery drills classify
missing, resumable, terminal, destructive-replay-blocked, and operator-action
required states as local evidence only. Provider health is limited to static
operator-owned bindings and must not discover, substitute, or widen providers.
Retention plans are dry-run classifications only; they do not delete, move,
compact, upload, or mutate runtime evidence.

Chio treaty-bound provenance adds the first bounded cross-kernel admission
evidence lane. Governance ladder manifests declare action class mode,
destructive posture, consistency model, co-sign requirement, and required
evidence for one kernel. A treaty scope pins the participating kernels and the
exact ladder manifest hashes supplied by verifier-owned inputs. The ladder
intersection chooses the strict shared mode and fails closed on stale manifest
material, missing participants, unknown action classes, destructive downgrade,
or consistency mismatch. Cross-boundary admission reports are local evidence
only and must be denied when required treaty evidence is missing. Continuation
and receipt-lineage statements keep `verified`, `observed`, `asserted`,
`unverifiable`, and `rejected` evidence classes distinct. Buyer attestation
packets may bind budget references, but they do not claim settlement. A buyer
packet is accepted only when the packet hashes match verified lineage and the
lineage remains verified rather than asserted.

Chio treaty-to-buyer review adds a local buyer-facing loop over the
treaty-bound evidence. A buyer review package binds the buyer packet, admission
report, continuation, lineage bundle, bilateral invocation, workflow receipt,
proof package, verifier report, and runtime run report by artifact role,
relative path, byte count, and SHA-256. Verification hydrates those artifacts
before accepting the package, rejects asserted lineage as verified evidence,
and records structured checks explaining the accepted or rejected state. The
review loop is local evidence only: budget references remain non-settlement
references, hidden predicates remain unsupported, and package-carried material
does not become a trust root.

Chio live treaty-to-buyer closure is the assurance gate that upgrades those
local artifacts from fixture-shaped evidence to bounded runtime evidence. The
closure requires verifier-owned treaty runtime state, pre-dispatch denial in
the kernel, strict Chio DSSE with treaty binding references over real
request, outcome, and receipt hashes, bounded lineage graph closure, and proof
regeneration accepted by the existing proof verification implementation. Hash-only
self-attestation, copied static proof packages, compatibility-only bilateral
predicates, and package-carried trust roots do not satisfy closure. The
boundary remains local evidence only and does not add dynamic trust, settlement
finality, hidden predicates, new transports, FROST, or pheromone-driven
authority decisions.

`POST /v1/registry/market/fees/issue`,
`POST /v1/registry/market/penalties/issue`, and
`POST /v1/registry/market/penalties/evaluate` are Chio's bounded open-market
economics surfaces. They sign one fee-schedule artifact over explicit
namespace, actor-kind, operator-id, and admission-class scope plus publication,
dispute, and market-participation fees and bond requirements, then sign one
market-penalty artifact over matched listing, trust-activation, governance
charter, sanction or appeal case, abuse class, bond class, and penalty amount.
Evaluation requires signature-valid listing, fee-schedule, governance, and
penalty artifacts; fail-closed freshness for fee schedules and governance
authority; explicit scope matching against the current publisher, actor kind,
and admission class; matching bond requirement and slashability; currency-safe
penalty sizing; and valid prior-penalty linkage for reversal. This is explicit
bounded market discipline, not permissionless slashing, global penalties, or
ambient trust admission. Under adversarial multi-operator conditions, invalid
mirrored listing signatures remain visible but untrusted, divergent replica
freshness yields non-admission rather than silent preference, and governance or
market-penalty evaluation rejects trust activations not issued by the
governing local operator.

`GET /v1/reports/facility-policy` evaluates that scorecard plus runtime
assurance and optional tool-server certification posture into one bounded
capital-allocation report. `POST /v1/facilities/issue` signs and persists that
same report as a facility artifact, and `GET /v1/reports/facilities` projects
current lifecycle state over persisted facility rows. These surfaces make the
following operator claims explicit:

- Chio can grant one bounded single-currency credit limit with utilization,
  reserve, concentration, and TTL terms when score, assurance, and
  certification posture are sufficient
- Chio can deny allocation explicitly when runtime assurance or required
  certification evidence is missing
- Chio can force manual review when the book is mixed-currency or still carries
  settlement-risk posture that Chio will not auto-net or auto-price away
- Chio can also force manual review when runtime-assurance evidence spans
  multiple verifier families, because Chio will not auto-allocate capital from
  heterogeneous assurance provenance alone
- supersession and expiry change operator-visible lifecycle state without
  rewriting the previously signed facility artifact

This is still a bounded policy surface, not a live capital market. Chio does
not lock collateral, execute bonds, slash reserves, clear external capital, or
claim autonomous insurer-rate setting from this phase alone.

`GET /v1/reports/credit-backtest` is Chio's replay and qualification surface for
that same credit layer. It evaluates one subject-scoped historical window set
over signed exposure, scorecard, and facility-policy logic and returns:

- one bounded set of replay windows with stable `since`/`until` timestamps
- one explicit drift vocabulary covering score-band shifts, facility
  disposition changes, stale evidence, over-utilization, missing runtime
  assurance, missing active certification, pending backlog, failed backlog,
  and mixed-currency books
- one aggregate summary of drift, denial, manual-review, and stale-evidence
  counts suitable for qualification reports and milestone audits

Backtests are intentionally deterministic and fail closed on missing subject
scope or invalid window ranges. They replay Chio's current bounded policy over
historical evidence; they do not invent a second mutable actuarial store.

`GET /v1/reports/provider-risk-package` is Chio's signed provider-facing capital
review package. It returns:

- one signed exposure ledger and one signed credit scorecard over the same
  scoped evidence set
- one current facility-policy evaluation plus the latest persisted facility
  snapshot when one exists
- one runtime-assurance and certification posture summary for the scoped book
- one recent-loss history derived from the newest matching failed or still
  action-required settlement rows rather than from an arbitrary paged exposure
  slice
- one provider-facing evidence reference set suitable for external capital
  review without re-querying live operator state

This package is still a bounded review artifact rather than a live financing
contract. Chio can now package honest credit posture for external capital review,
but it still does not bind external capital, execute reserves, or run a
liability market from the current automation profile alone.

`chio.risk.comptroller-report.v1` is the launch risk control projection. It is
a signed verifier-facing artifact over one transaction passport, commerce order,
subject, facility state, coverage binding, reserve ledger, sanction bridge,
appeal state, capital instruction set, reconciliation summary, actuarial
backtest, and bounded insurance copy statement. The report folds the launch
facility-state, coverage, reserve, sanction, appeal, capital, and actuarial
sub-reports into one artifact for the first release; verifiers must treat those
folded sections as required contract fields, not optional prose. Verification
fails closed unless the report is `verified`, has risk state `reconciled`,
binds the same passport id, order id, subject, currency, reserve, coverage,
payout, settlement, and policy ids across all folded sections, carries
`claim.risk.comptroller_report_bound`, and passes deterministic replay of the
facility lifecycle from `evidence_cold` to the declared current state.

The comptroller report is not an autonomous insurer or capital-market claim.
It only proves that Chio reconciled the signed risk evidence supplied to the
proof. The verifier rejects zero or over-consumed reserves, reserve currency
drift, missing coverage, coverage outside the order or subject, unsupported
facility states, duplicate reserve consumption, market slash without an
explicit sanction and reserve bridge, open appeals that block payout, payout
instructions that were already externally observed, invalid actuarial windows,
failed backtests, and insurance copy whose maximum coverage exceeds the
actuarial support. Standalone schema names such as facility-state report,
claim-case file, sanction-reserve ledger, capital adequacy report, and
actuarial-backtest report are future split points unless and until they are
registered as signed artifacts; launch verifiers consume their semantics
through `chio.risk.comptroller-report.v1`.

`GET /v1/reports/capital-book` is Chio's signed live source-of-funds ledger for
that same bounded credit layer. It returns:

- one subject-scoped capital-book summary over receipts, facilities, bonds, and
  loss-lifecycle state
- one attributable facility-commitment source plus one reserve-book source when
  the scoped book can be represented honestly
- one event stream over committed, held, drawn, disbursed, released, repaid,
  and impaired capital state linked back to facility, bond, loss-lifecycle, and
  receipt evidence
- one explicit support boundary that says Chio is authoritative about the source
  attribution it emits but still does not auto-net across currencies or execute
  external custody movement

This surface is intentionally conservative. It fails closed when a subject
scope is missing, receipt counterparty attribution is missing or contradictory,
the selected book spans multiple currencies, more than one live facility or
bond would need to be blended into one source-of-funds story, or no active
granted facility exists to explain committed capital.

`POST /v1/capital/instructions/issue` is Chio's custody-neutral reserve and
escrow instruction surface over that same capital book. It signs one explicit
instruction artifact carrying:

- one subject-scoped capital-book query and one resolved live source
- one typed action `lock_reserve`, `hold_reserve`, `release_reserve`,
  `transfer_funds`, or `cancel_instruction`
- for `transfer_funds`, one governed receipt id plus one derived
  completion-flow row id so downstream settlement stays bound to exactly one
  receipt-scoped economic flow
- one explicit authority chain with role, principal, approval time, and
  expiry for each approving or executing actor
- one explicit execution window plus one custody-neutral rail descriptor
- one separate intended-state versus reconciled-state projection so Chio never
  claims external execution from intent alone
- one bounded evidence set tying the instruction back to facility, bond, and
  capital-book event provenance

This surface is also intentionally conservative. It fails closed when:

- the requested action does not match the selected live source kind
- the execution window is already expired or internally contradictory
- any authority step is stale, malformed, or expires before the execution
  window closes
- the authority chain does not include both source-owner approval and the
  named custody-provider execution step
- the intended amount is zero, overstates the available live source amount, or
  mixes currency with the selected capital source
- a `transfer_funds` instruction omits `governedReceiptId`, omits its derived
  completion-flow row id, resolves to zero or multiple disburse events on the
  selected source, or asks for an amount that does not match that one disburse
  event exactly
- observed external execution falls outside the execution window or does not
  match the intended amount exactly

Chio signs the instruction contract it emits. By itself, this endpoint remains a
custody-neutral intent surface and does not prove external execution. Under
the shipped official web3 stack, a separate
`chio.web3-settlement-dispatch.v1` artifact may bind that instruction to one
escrow and bond-vault lane, but observed settlement still must reconcile
through explicit proof artifacts.

`POST /v1/capital/allocations/issue` is Chio's simulation-first live
capital-allocation surface for governed actions over that same capital book. It
signs one explicit allocation-decision artifact carrying:

- one subject-scoped capital-book query plus one selected governed receipt
- one resolved facility-commitment source, one optional reserve-book source,
  and one typed allocation outcome `allocate`, `queue`, `manual_review`, or
  `deny`
- one explicit authority chain, execution window, and custody-neutral rail
  descriptor for the eventual capital movement
- one current outstanding, reserve, utilization, and concentration view tied
  back to active facility terms when a live facility already exists
- one bounded instruction-draft set describing the transfer and reserve actions
  Chio would take if the allocation can proceed

This surface is intentionally conservative too. It fails closed when:

- the scoped query does not resolve exactly one approved actionable governed
  receipt or the caller omits `receiptId` while multiple such receipts exist
- the selected receipt lacks governed `max_amount` truth or contradicts the
  scoped subject/currency posture
- the authority chain is stale, the custody step is missing, or the shared
  execution envelope is internally contradictory
- no active live source-of-funds state can explain the requested governed
  action honestly
- reserve backing would need to be created implicitly rather than tied to one
  explicit reserve book
- concentration or utilization posture prevents immediate allocation, in which
  case Chio emits an explicit `deny` or `queue` decision instead of inferring
  execution

Chio signs the allocation decision it emits, but the allocation artifact itself
is not proof of external execution. Under the shipped official web3 stack,
execution remains a separate dispatch-plus-settlement-receipt artifact family,
so allocation stays the deterministic operator and counterparty contract for
what Chio would allocate and why.

This is Chio's current live-capital boundary. Chio now proves explicit
source-of-funds state, custody-neutral instruction contracts, simulation-first
governed allocation, and one bounded official web3 execution surface over
canonical economic evidence while keeping regulated-role assumptions explicit
instead of ambient.

The shipped official web3 execution surface is artifact-driven rather than
permissionless. It consists of `chio.web3-trust-profile.v1`,
`chio.web3-contract-package.v1`, `chio.web3-chain-configuration.v1`,
`chio.anchor-inclusion-proof.v1`, `chio.anchor-inclusion-proof.v2`,
`chio.oracle-conversion-evidence.v1`,
`chio.web3-settlement-dispatch.v1`,
`chio.web3-settlement-execution-receipt.v1`, and
`chio.web3-qualification-matrix.v1`. Those artifacts bind one official
Base-first escrow and bond-vault lane back to Chio receipts, checkpoints, and
capital state without mutating prior signed truth or hiding custody
assumptions. That surface is now backed locally by one packaged Solidity
contract family in `contracts/`, one artifact-derived Rust Alloy bindings
target in `crates/economy/chio-web3-bindings/`, and one bounded local-devnet
qualification run. Four contracts in that package are immutable; the one
exception is `IChioIdentityRegistry`, which remains owner-managed and mutable
for operator registration and key-binding changes. Chio therefore does not
claim universal immutability for every contract surface in the package.

The shipped bounded `chio-link` oracle-runtime surface is explicit rather than
ambient. It consists of one `chio-link` runtime profile plus a pinned operator
configuration artifact, one runtime-report schema instance,
one receipt-boundary policy note, and one qualification matrix. That surface
binds cross-currency budget enforcement to pinned Chainlink or Pyth inputs,
trusted Base and standby Arbitrum chain inventory, sequencer downtime and
recovery gating, explicit operator pause or disable controls, and
conservative conversion margins recorded back into receipt financial metadata.
`chio_link_runtime_v1` is the only supported runtime FX authority model on this
surface; backend labels such as Chainlink or Pyth remain subordinate source
details inside that authority envelope. It is backed locally by
`crates/economy/chio-link/`, kernel integration in `crates/kernel/chio-kernel/`, and
deterministic qualification coverage rather than live external infrastructure.
The auxiliary `ChioPriceResolver` contract is a contract-side reference reader,
not a replacement authority for kernel charging or settlement receipts. This
surface is not a universal oracle network, automatic cross-chain execution
lane, or justification to widen spend beyond configured pair, chain, and
freshness policy.

The shipped bounded `chio-settle` runtime surface is also explicit rather than
ambient. It consists of one `chio-settle` runtime profile, one representative
finality-report artifact, one representative Solana settlement-preparation
artifact, one qualification matrix, and one operator runbook. That surface
binds approved capital instructions to explicit ERC-20 approval, escrow
create/release/refund, and bond-vault lifecycle calls; projects chain state
back into canonical `chio.web3-settlement-execution-receipt.v1` artifacts with
tiered confirmation and dispute-window policy; preserves reserve requirement
metadata from signed bond artifacts while only locking collateral on-chain in
the bond vault; and keeps Solana support
bounded to Ed25519 verification plus canonical instruction preparation rather
than live broadcast. It is backed locally by `crates/economy/chio-settle/`, the shared
official contracts in `contracts/`, and one runtime-devnet qualification lane.
Those lanes are only claimed when Chio also has local durable receipt storage,
kernel-signed checkpoints, and evidence exports that keep checkpoint signer
truth bound to the receipt kernel key.
It is not permissionless settlement routing, automatic dispute adjudication,
cross-chain fund movement, gas sponsorship, or a claim that Chio itself is the
custodian or regulated insurer.

The shipped public-settlement proof surface is likewise explicit rather than
ambient. It consists of two artifacts defined in
`crates/economy/chio-web3/src/settlement_proof.rs`.
`chio.web3-settlement-proof-bundle.v1` binds one transaction passport and
commerce order to a validated
`chio.web3-settlement-execution-receipt.v1`, an order binding, a chain
snapshot (escrow state plus optional bond, block, and beneficiary
identity-binding snapshots), optional public-witness and dispute snapshots,
optional trust-market references, required and observed confirmation counts,
a dispute posture, and an optional detached `ed25519-rfc8785-v1` bundle
signature. `chio.public-settlement-verifier-report.v1` is the typed verdict
that `verify_public_settlement_proof` emits over such a bundle: it carries
the recomputed settlement state, chain, public-witness, finality, and
dispute context, optional trust-market context, and the explicit
`claim.public_settlement.*` verified-claim list. Verification requires an
independent chain head: finality MUST be checked against a chain
observation that does not come from the bundle itself, and a missing
independent head rejects the bundle. Verifier surfaces accept that head
either as pinned JSON (`CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON`,
which takes precedence) or through the bounded independent-chain recheck
lane: when `CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL` is set, the
`chio proof` verifier and the Proof Room upload verifier fetch
`eth_blockNumber` plus the observed block header via `eth_getBlockByNumber`
over the section 8.4 egress contract and require chain-id,
observed-block-number, and block-hash agreement with the bundle, an
independent head at or beyond the observed block, and independent
confirmations at or above the bundle's required threshold that are not
exceeded by the bundle's observed confirmations. A missing, mismatched, or
under-confirmed independent head rejects the bundle fail-closed; the
recheck lane never widens acceptance beyond the pinned verifier trust
policy (trusted signer keys, allowed chain ids, mainnet blocking, and
minimum-confirmation floors).

The shipped bounded web3-operations surface is explicitly scoped.
It consists of one `CHIO_WEB3_OPERATIONS_PROFILE.md`, one anchor runtime-report
example, one settlement runtime-report example, one operations qualification
matrix, one deployment-promotion policy, one focused readiness audit, and one
reviewer-facing external qualification matrix plus partner-proof package. That
surface binds operator visibility to explicit indexer lag, drift, replay,
finality, and emergency-mode semantics, and it keeps local qualification,
operator-reviewed templates, and external publication holds separate instead
of implying that a green local devnet run already means live deployment. The
hosted release bundle under `target/release-qualification/web3-runtime/`
remains the publication-facing evidence family; local evidence alone is not a
public-release claim.

The shipped bounded autonomous insurance-automation surface is also
artifact-driven rather than ambient. It consists of
`chio.autonomous-pricing-input.v1`,
`chio.autonomous-pricing-authority-envelope.v1`,
`chio.autonomous-pricing-decision.v1`,
`chio.capital-pool-optimization.v1`,
`chio.capital-pool-simulation-report.v1`,
`chio.autonomous-execution-decision.v1`,
`chio.autonomous-rollback-plan.v1`,
`chio.autonomous-comparison-report.v1`,
`chio.autonomous-drift-report.v1`, and
`chio.autonomous-qualification-matrix.v1`. Those artifacts bind one bounded
autonomous pricing lane back to underwriting, credit, capital, liability, and
official-web3 truth while keeping execution subordinate to explicit control
envelopes, rollback plans, human interrupt contacts, and operator-visible
comparison evidence.

`GET /v1/reports/bond-policy` evaluates canonical exposure plus the latest
active granted facility into one reserve-state report. `POST /v1/bonds/issue`
signs and persists that same report as a bond artifact, and
`GET /v1/reports/bonds` projects current lifecycle state over persisted bond
rows. These surfaces make the following operator claims explicit:

- Chio can express reserve posture as one typed `lock`, `hold`, `release`, or
  `impair` decision over canonical exposure and the latest active facility
- bond artifacts preserve collateral amount, reserve requirement, outstanding
  exposure, coverage ratio, and capital-source provenance back to the active
  facility terms
- mixed-currency reserve accounting fails closed with `409 Conflict` instead
  of auto-netting or inventing blended collateral state
- supersession changes operator-visible lifecycle state without rewriting the
  previously signed bond artifact

This is now reserve-backed runtime autonomy gating with an intentionally
bounded execution scope. Chio can require an explicit autonomy context plus an
active signed delegation bond before delegated or autonomous governed
execution proceeds, and it fails closed when bond lifecycle, support boundary,
reserve disposition, call-chain, or runtime-assurance prerequisites are
missing. Chio still does not slash reserves, execute external escrow, or claim
complete loss or recovery lifecycle semantics from phases `85` and `86`
alone.

`GET /v1/reports/bond-loss-policy` now evaluates one explicit bond-loss
lifecycle step over the persisted bond plus canonical recent-loss evidence.
`POST /v1/bond-losses/issue` signs and persists that same evaluation as an
immutable lifecycle artifact, and `GET /v1/reports/bond-losses` projects the
current event stream for operator review. These surfaces make the following
claims explicit:

- Chio records delinquency, recovery, reserve-release, reserve-slash, and
  write-off as
  separate immutable signed artifacts instead of mutating bond, facility, or
  receipt rows in place
- delinquency booking is derived from the newest matching failed-loss evidence
  rather than from a truncated exposure page
- recovery and write-off amounts are bounded by previously recorded
  outstanding delinquency, with currency mismatches failing closed
- reserve release and reserve slash are executable reserve-control artifacts
  with explicit `authorityChain`, `executionWindow`, custody-rail, optional
  `observedExecution`, reconciliation-state, and appeal-window semantics
- reserve release requires both cleared delinquency and no unbooked remaining
  outstanding exposure, while reserve slash requires outstanding delinquency
  plus available reserve backing
- stale authority, missing execution metadata, contradictory observed movement,
  and invalid appeal windows fail closed during reserve-control issuance

This is still bounded lifecycle accounting rather than a claims network or
live escrow engine. Phases `87`, `113`, `115`, and `116` now make bond-backed
loss and recovery state auditable and add a bounded claims-payment plus
settlement lane through explicit payout instructions, payout receipts,
settlement instructions, and settlement receipts, but Chio still does not
execute insurer placement or open-ended cross-organization recovery clearing
from reserve-control state alone.

### 9.1 Launch And Standards Boundary

The current launch and standards-facing Chio profile is intentionally bounded to
shipping evidence plus deterministic operator-visible runtime evaluation:

- signed receipts, checkpoints, and evidence-export primitives
- Chio portable-trust and certification surfaces
- signed behavioral-feed export
- signed underwriting-input snapshot
- deterministic underwriting-decision report over canonical evidence
- signed underwriting decisions with explicit budget, premium, and appeal
  linkage semantics
- non-mutating underwriting simulation over canonical evidence
- signed exposure-ledger export with per-currency economic-position totals
- signed credit-scorecard export with explicit probation and anomaly semantics
- bounded facility-policy evaluation plus signed facility artifacts and
  lifecycle reporting
- deterministic credit backtests over historical evidence windows
- signed provider-facing risk packages for external capital review
- reserve-backed autonomy-tier gating over explicit delegation-bond posture
- immutable bond-loss lifecycle artifacts over delinquency, recovery,
  reserve-release, reserve-slash, and write-off state, plus executable reserve
  release/slash controls with explicit authority, reconciliation, and appeal
  state
- non-mutating bonded-execution simulation with operator control policy,
  kill-switch semantics, and sandbox qualification over signed bond truth
- curated liability-provider registry artifacts with explicit jurisdiction,
  coverage-class, currency, and evidence-requirement policy plus fail-closed
  provider resolution
- delegated pricing-authority artifacts linked to one provider or
  regulated-role envelope plus underwriting, facility, and capital-book truth,
  with explicit coverage and premium ceilings plus fail-closed stale-authority
  rejection
- provider-neutral liability quote-request, quote-response, placement, and
  bound-coverage artifacts over one signed provider-risk package, with
  fail-closed stale-provider, expiry, mismatch, and unsupported-policy checks
- automatic coverage-binding decisions that remain subordinate to delegated
  pricing-authority ceilings and fail closed on out-of-envelope coverage or
  premium requests
- immutable liability claim-package, provider-response, dispute, and
  adjudication artifacts linked back to bound coverage, exposure, bond, loss,
  and receipt evidence, with fail-closed oversized-claim and invalid-dispute
  state checks
- automatic claim-payout instruction and payout-receipt artifacts that stay
  subordinate to adjudicated claim outcomes and capital-execution truth, with
  fail-closed duplicate, stale-window, and mismatch handling
- claim-settlement instruction and settlement-receipt artifacts that make one
  reimbursement or recovery topology explicit over matched payout and
  capital-book truth, with fail-closed stale-authority and counterparty- or
  amount-mismatch handling
- runtime-assurance-aware issuance and governed-execution constraints

The current liability-market claim is intentionally bounded: Chio now proves a
curated provider discovery and selection admission flow, delegated
pricing-authority, quote/bind, and claim/dispute/adjudication/payout-and-
settlement orchestration layer over canonical evidence, but not an insurer
network, open-ended recovery-clearing network, open-ended autonomous pricing
beyond the documented bounded authority-envelope and rollback lane, or
permissionless market.

External launch, partner, or standards materials should derive claims from this
protocol document, the release-qualification corpus, and the release audit.
They must not imply permissionless or arbitrary external capital dispatch
beyond the documented official web3 lane, implicit regulated-actor status,
autonomous insurer-rate setting beyond the documented bounded autonomous-pricing
surface, claim or dispute adjudication beyond the documented liability-market
surface, or theorem-prover completion beyond the boundary and assumptions
defined in Section 5.4.

## 10. Portable Trust And Federation

### 10.1 Agent Passport

Chio issues these portable-trust schema identifiers:

| Artifact | Schema |
| --- | --- |
| Agent passport | `chio.agent-passport.v1` |
| Verifier policy | `chio.passport-verifier-policy.v1` |
| Presentation challenge | `chio.agent-passport-presentation-challenge.v1` |
| Presentation response | `chio.agent-passport-presentation-response.v1` |
| Cross-issuer portfolio | `chio.cross-issuer-portfolio.v1` |
| Cross-issuer trust pack | `chio.cross-issuer-trust-pack.v1` |
| Cross-issuer migration | `chio.cross-issuer-migration.v1` |

The current shipped semantics are:

- issuer and subject identities inside shipped Chio passport artifacts
  currently remain `did:chio`
- a passport may contain multiple credentials from different issuers as long as
  they all bind to one subject
- verifier evaluation remains per credential
- acceptance requires at least one credential to satisfy the verifier policy
- Chio now also defines one bounded cross-issuer portfolio contract over those
  existing passport artifacts
- portfolio visibility, possession, and local trust activation remain separate
- cross-subject or cross-issuer rebinding requires one explicit signed
  migration artifact; Chio does not infer continuity from overlapping display
  claims or discovery visibility
- local portfolio activation requires one explicit signed trust pack and still
  evaluates per entry rather than inventing a synthetic cross-issuer trust
  score
- replay-safe challenge verification can be backed by durable SQLite state
- Chio may expose one public holder transport over stored challenge state:
  `GET /v1/public/passport/challenges/{challenge_id}` and
  `POST /v1/public/passport/challenges/verify`
- non-Chio schema identifiers are rejected instead of treated as compatibility
  aliases

### 10.1.1 OID4VCI-Compatible Passport Issuance

Chio now ships one conservative OID4VCI-compatible issuance lane for the
existing passport artifact. The transport surface is:

- `GET /.well-known/openid-credential-issuer`
- `POST /v1/passport/issuance/offers`
- `POST /v1/passport/issuance/token`
- `POST /v1/passport/issuance/credential`

The profile is intentionally narrow:

- `POST /v1/passport/issuance/offers` is operator-authenticated and creates one
  replay-safe offer over an existing Chio passport artifact
- the always-available native credential profile is configuration id
  `chio_agent_passport` with format `chio-agent-passport+json`
- when the issuer has an explicit signing key, it may also advertise two
  projected portable profiles:
  `chio_agent_passport_sd_jwt_vc` with format `application/dc+sd-jwt`, and
  `chio_agent_passport_jwt_vc_json` with format `jwt_vc_json`
- when any projected portable profile is advertised, the issuer also exposes
  `GET /.well-known/jwks.json`,
  `GET /.well-known/chio-passport-sd-jwt-vc`, and
  `GET /.well-known/chio-passport-jwt-vc-json`
- issuer metadata may advertise `chioProfile.passportStatusDistribution` when
  the operator has configured a public read-only lifecycle resolve plane
- the native delivered credential remains the existing Chio `AgentPassport`
  artifact, so issuer and subject identities inside the credential stay
  `did:chio`
- the projected portable credential is derived from the same verified passport
  truth and does not establish a second Chio identity root
- the projected `application/dc+sd-jwt` profile keeps `iss`, `sub`, `vct`,
  `cnf`, `chio_passport_id`, `chio_subject_did`, and `chio_credential_count`
  anchored in the signed payload and only permits `chio_issuer_dids`,
  `chio_merkle_roots`, and `chio_enterprise_identity_provenance` as supported
  disclosures
- the projected `jwt_vc_json` profile keeps `iss`, `sub`, `cnf.jwk`,
  `vc.type`, `vc.credentialSubject.id`,
  `vc.credentialSubject.chioPassportId`,
  `vc.credentialSubject.chioCredentialCount`,
  `vc.credentialSubject.chioIssuerDids`,
  `vc.credentialSubject.chioMerkleRoots`, and
  `vc.credentialSubject.chioEnterpriseIdentityProvenance` anchored in the
  signed JWT VC payload, and it declares the same Chio claim catalog with
  `supportsSelectiveDisclosure=false` so those Chio claims are always disclosed
  in this profile
- credential delivery may include an
  `chioCredentialContext.passportStatus` sidecar that binds the delivered
  passport id to one or more lifecycle resolve URLs plus a cache hint
- the HTTPS `credential_issuer` is a transport and discovery identifier; it is
  not a new trust root
- pre-authorized codes and issuance access tokens are single-use and
  short-lived
- if an issuer advertises portable lifecycle support, offer creation and
  credential delivery fail closed unless the target passport is already
  published active with at least one resolve URL
- unsupported profile ids, mismatched subjects, mismatched formats, or issuer
  metadata conflicts fail closed

Portable lifecycle resolution itself remains Chio-native and operator-scoped:

- the default trust-control public read surface is
  `GET /v1/public/passport/statuses/resolve/{passport_id}`
- each distributed `resolve_url` is a base endpoint; portable consumers
  resolve one passport by appending `/{passport_id}`
- any distributed `resolve_url` must be paired with an explicit
  `cache_ttl_secs`; advertising public lifecycle discovery without a freshness
  bound is invalid
- the resolution document remains the richer Chio lifecycle shape with
  `active`, `stale`, `superseded`, `revoked`, and `notFound`, plus
  `updated_at` on every non-`notFound` response
- only `active` is a healthy portable lifecycle state
- `stale` means the artifact is still the current published passport, but the
  last lifecycle update is older than the advertised TTL and must be denied
  fail closed
- `superseded` is not silently collapsed into revocation
- `notFound`, malformed lifecycle responses, stale lifecycle state, and
  lifecycle distributions that omit TTL are not healthy states for portable
  consumers

Chio now also ships one bounded public discovery layer over those existing
issuer and verifier metadata surfaces:

- `GET /v1/public/passport/discovery/issuer`
- `GET /v1/public/passport/discovery/verifier`
- `GET /v1/public/passport/discovery/transparency`

That discovery layer is intentionally conservative:

- issuer discovery is one signed, versioned, TTL-bounded projection over the
  already-published `/.well-known/openid-credential-issuer` metadata and its
  configured portable lifecycle distribution
- verifier discovery is one signed, versioned, TTL-bounded projection over the
  already-published `/.well-known/chio-oid4vp-verifier` metadata, verifier
  `JWKS`, and request-URI prefix
- transparency is one signed snapshot over the current issuer and verifier
  discovery documents, carrying per-entry hashes plus publication and expiry
  windows for visibility and manual review
- every discovery document carries explicit import guardrails requiring
  informational-only visibility, explicit local policy import, and manual
  review before any activation
- missing authority signing material makes the public discovery routes
  unavailable
- unsigned, stale, malformed, contradictory, or incomplete discovery
  documents fail closed
- discovery visibility, searchability, or fetchability never equals local
  trust activation or runtime admission

Cross-issuer portfolio composition remains bounded and explicit:

- a cross-issuer portfolio is a holder- or operator-assembled evidence set over
  existing Chio passport artifacts, not a new synthetic identity root
- a portfolio may contain visible imported entries that are not locally
  activated
- imported or migrated entries remain distinguishable from native local
  entries through explicit `sourceKind` and optional `source`
- subject rebinding into the portfolio subject requires one signed
  cross-issuer migration artifact with explicit issuer, subject, prior
  passport, and time-bound continuity references
- trust-pack policy may activate issuers, profile families, entry kinds,
  migration ids, certification references, and active lifecycle requirements,
  but it must not widen visibility into automatic federation admission
- duplicate migration identifiers, mismatched lifecycle projections, unknown
  migration references, and subject rebinding without an explicit migration all
  fail closed
- portfolio acceptance remains per entry; Chio may report activated entries and
  activated issuers, but it does not publish a synthetic cross-issuer trust
  score

This protocol does not claim support for generic `ldp_vc`, generic JWT VC
interoperability beyond Chio's documented passport profile family, generic
SD-JWT VC interoperability beyond Chio's documented passport profile family, or
permissionless multi-operator issuer, verifier, or wallet discovery beyond
Chio's documented public identity-profile, wallet-directory, and routing-
manifest contract.

### 10.1.2 OID4VP Verifier Interop

Chio now ships one narrow verifier-side OID4VP bridge over the projected
passport credential lane. The public transport surface is:

- `GET /.well-known/chio-oid4vp-verifier`
- `GET /.well-known/jwks.json`
- `POST /v1/passport/oid4vp/requests`
- `GET /v1/public/passport/wallet-exchanges/{request_id}`
- `GET /v1/public/passport/oid4vp/requests/{request_id}`
- `GET /v1/public/passport/oid4vp/launch/{request_id}`
- `POST /v1/public/passport/oid4vp/direct-post`

`POST /v1/passport/oid4vp/requests` now returns three coordinated views of
the same verifier transaction:

- the signed OID4VP request object
- the OID4VP request transport bundle
- one transport-neutral wallet exchange descriptor plus one canonical
  transaction-state object

The verifier may also opt into one bounded `identityAssertion` object on that
request. When present, Chio treats it as continuity metadata rather than proof
of new authority:

- `verifierId` must match the HTTPS verifier `client_id`
- `boundRequestId` must match the canonical Chio wallet exchange id and OID4VP
  `request_id`
- `subject` and `continuityId` carry verifier-local continuity context
- optional `provider` and `sessionHint` may describe the source of that
  continuity
- `issuedAt` and `expiresAt` must remain fresh and must not outlive the parent
  OID4VP request
- the same canonical object is echoed through the wallet-exchange projection,
  OID4VP verification result, and hosted `chio_transaction_context` lane when
  the verifier chooses to reuse it there

`GET /v1/public/passport/wallet-exchanges/{request_id}` exposes that neutral
descriptor and current transaction state without widening verifier admin
authority. The descriptor keeps Chio's trust roots aligned:

- `exchange_id` is the canonical Chio wallet transaction identifier and is
  currently aligned to the OID4VP `request_id`
- replay anchors are the existing signed verifier request id, nonce, state,
  and request-object hash
- same-device launch remains one `openid4vp://authorize?request_uri=...`
  artifact
- cross-device and relay delivery currently reuse one HTTPS verifier launch
  URL instead of inventing a second public verifier authority
- canonical transaction states are `issued`, `consumed`, and `expired`
- optional identity assertions stay derived from that same canonical request
  id and do not create a second mutable session store

The profile is intentionally narrow:

- verifier identity is one HTTPS `client_id` with
  `client_id_scheme=redirect_uri`
- request objects are signed with EdDSA and fetched by `request_uri`
- same-device launch uses `openid4vp://authorize?request_uri=...`
- cross-device launch is one HTTPS URL that resolves back to that same
  `request_uri`-based verifier transaction
- relay-capable delivery reuses that same HTTPS verifier transaction rather
  than introducing a second launch trust root
- holder responses use `response_type=vp_token` and
  `response_mode=direct_post.jwt`
- Chio currently supports exactly one requested credential with format
  `application/dc+sd-jwt` and type
  `https://chio.world/credentials/types/chio-passport-sd-jwt-vc/v1`
- verifier trust bootstrap is one Chio verification metadata document plus one
  verifier `JWKS`
- verifier or issuer key rotation may preserve active request and credential
  validation only when the rotated trusted keyset is still published through
  that `JWKS`
- any identity assertion remains optional and verifier-scoped; Chio does not
  make external identity providers mandatory for wallet presentation
- missing metadata, stale requests, replayed or contradictory wallet exchange
  state, stale or mismatched identity assertions, unsupported request shapes,
  stale lifecycle state, mismatched issuers, or untrusted keys fail closed

This protocol does not claim generic OID4VP wallet compatibility, SIOP,
DIDComm, or permissionless verifier marketplace semantics beyond this
Chio-specific verifier profile plus the bounded public identity-network routing
contract.

### 10.1.3 Holder Presentation Transport

Chio now ships one conservative holder-facing transport over the existing
passport presentation artifacts. The proof objects do not change:

- the verifier/admin still creates the signed
  `chio.agent-passport-presentation-challenge.v1`
- the holder still signs the existing
  `chio.agent-passport-presentation-response.v1`
- verifier replay truth still lives in the durable challenge store

The transport surface is intentionally narrow:

- admin or verifier challenge creation remains on
  `POST /v1/passport/challenges`
- admin or verifier challenge verification remains on
  `POST /v1/passport/challenges/verify`
- optional public holder fetch is
  `GET /v1/public/passport/challenges/{challenge_id}`
- optional public holder submit is
  `POST /v1/public/passport/challenges/verify`

When trust-control returns transport metadata for a created challenge, it uses
one Chio-native contract with:

- `challengeId`
- `challengeUrl`
- `submitUrl`

The contract is challenge-bound, not session-marketplace state:

- public fetch is read-only and resolves one already-stored verifier challenge
  by `challengeId`
- public submit verifies the holder response against stored verifier truth and
  consumes the replay-safe challenge record on success
- public routes do not expose verifier policy CRUD, challenge creation, or
  other admin mutation
- missing `challengeId`, expired challenges, consumed challenges, malformed
  stored challenge state, or holder submissions that do not match stored
  verifier truth fail closed

This transport is Chio-specific. It coexists with the separate OID4VP verifier
profile above, but it does not itself imply generic OID4VP, DIDComm, or other
wallet transport compatibility claims beyond the bounded public identity-
network contract described below.

### 10.1.4 Public Identity Network Artifacts

Chio now also ships one bounded public identity-network artifact family over
the existing passport, projected credential, discovery, verifier, federation,
and cross-issuer substrate:

| Artifact | Schema |
| --- | --- |
| Public identity profile | `chio.public-identity-profile.v1` |
| Public wallet-directory entry | `chio.public-wallet-directory-entry.v1` |
| Public wallet-routing manifest | `chio.public-wallet-routing-manifest.v1` |
| Identity interop qualification matrix | `chio.identity-interop-qualification-matrix.v1` |

The bounded semantics are:

- every public identity profile must preserve `did:chio` as the provenance
  anchor while making any broader `did:web`, `did:key`, or `did:jwk`
  compatibility input explicit
- public identity profiles must preserve the existing Chio-native
  `chio-agent-passport+json` lane plus the projected `application/dc+sd-jwt`
  and `jwt_vc_json` passport families; they do not imply support for
  arbitrary VC formats
- wallet-directory entries are verifier-bound references over existing
  portable-trust and verifier-discovery state; they do not create a new trust
  root or ambient wallet-admission path
- wallet-routing manifests must require signed request objects, replay
  anchors, explicit response or relay URLs, and fail-closed handling for
  subject mismatch, stale routing state, or cross-operator issuer mismatch
- directory and routing artifacts remain informational or reviewable inputs
  unless a local verifier or operator explicitly imports them under policy
- the qualification matrix must cover supported and fail-closed scenarios for
  unsupported DID methods, unsupported credential families, directory
  poisoning, route replay, multi-wallet selection, and cross-operator issuer
  mismatch before Chio claims broader public identity interoperability

This artifact family does not claim generic OID4VP, SIOP, DIDComm, universal
wallet-network routing, automatic subject rebinding, or universal cross-issuer
trust. It is the strongest bounded public identity and wallet claim Chio makes
in this release.

### 10.2 Federation Artifacts

The shipped cross-org artifact schemas now use Chio-primary identifiers:

| Artifact | Schema |
| --- | --- |
| Evidence export manifest | `chio.evidence_export_manifest.v1` |
| Evidence export disclosure notice | `chio.evidence_export_disclosure_notice.v1` |
| Federation policy | `chio.federation-policy.v1` |
| Federated evidence share | `chio.federated-evidence-share.v1` |
| Federated delegation policy | `chio.federated-delegation-policy.v1` |

The supported contract includes:

- signed bilateral evidence-export policy documents
- verified import of exported evidence packages
- shared-evidence reporting without pretending foreign receipts are native local
  receipts
- parent-bound continuation from an imported upstream capability into a new
  local delegation anchor
- non-Chio evidence and delegation schema identifiers are rejected instead of
  treated as compatibility aliases
- tenant-scoped evidence export manifests carry a structured disclosure
  notice documenting which cross-tenant aggregate fields the signed
  checkpoint set inherently reveals; admin-all manifests omit the notice
  because the operator already requested cross-tenant visibility

### 10.3 Enterprise Identity Federation

Bearer-authenticated hosted sessions may normalize enterprise identity context
into:

- `authContext.method.federatedClaims`
- `authContext.method.enterpriseIdentity`

The current shipped provider-admin registry supports `oidc_jwks`,
`oauth_introspection`, `scim`, and `saml` record kinds. Invalid provider
records stay visible for operator diagnostics but are not eligible for
admission.

## 11. A2A Adapter Contract

`chio-a2a-adapter` is a thin bridge for A2A v1.0.0, not a new A2A wire
standard.

The current shipped behavior includes:

- Agent Card discovery
- `JSONRPC` and `HTTP+JSON` interface bindings
- `SendMessage`
- `SendStreamingMessage`
- `GetTask`
- `SubscribeToTask`
- `CancelTask`
- push-notification config create/get/list/delete
- fail-closed auth negotiation for bearer, OAuth/OpenID, HTTP Basic, API key,
  and mTLS
- optional durable task correlation through a file-backed registry
- explicit partner-admission policy by tenant, skill, security scheme, and
  allowed interface origin

Chio currently uses a frozen adapter-local metadata convention to route a call
to one A2A
skill:

```json
{
  "chio": {
    "targetSkillId": "research",
    "targetSkillName": "Research"
  }
}
```

That convention is explicit and is not presented as a core A2A protocol field.

## 12. Certification Contract

Chio ships signed certification checks with primary schema:

```text
chio.certify.check.v1
```

The local or trust-control-backed registry uses:

```text
chio.certify.registry.v1
```

The multi-operator discovery network uses:

```text
chio.certify.discovery-network.v1
```

The certification contract covers:

- evaluation of a declared conformance result corpus
- one fail-closed criteria profile today: `conformance-all-pass-v1`
- one fail-closed evidence profile today: `conformance-report-bundle-v1`
- signed artifacts with verdict, criteria profile, evidence profile, corpus
  digests, findings, and signer-bound evidence provenance
- registry publication, listing, get, resolve, revoke, and dispute recording
- public read-only metadata, resolve, search, and transparency surfaces per
  operator
- authenticated multi-operator publication, discovery aggregation, search,
  transparency, and policy-bound consume flows
- operator-facing resolution states: `active`, `revoked`, `superseded`,
  `not-found`
- dispute states: `open`, `under-review`, `resolved-no-change`,
  `resolved-revoked`
- compatibility `chio.certify.check.v1` and `chio.certify.registry.v1` remain valid
  for verification and load
- registry/discovery results that remain explicitly scoped to the operator that
  published them
- public discovery metadata that must fail closed when stale, mismatched, or
  malformed
- public listing consumption that remains explicitly policy-controlled and
  does not widen runtime trust from visibility alone

This is a governed public certification marketplace surface backed by signed
operator evidence. Search and transparency are signed visibility feeds rather
than public transparency-log semantics. It is not a permissionless trust
oracle, global mutable trust network, or automatic runtime-admission
mechanism.

Chio now also ships one bounded generic public registry substrate over those
existing operator-owned surfaces:

- `GET /v1/public/registry/namespace`
- `GET /v1/public/registry/listings/search`
- `POST /v1/registry/trust-activations/issue`
- `POST /v1/registry/trust-activations/evaluate`
- one signed namespace artifact that makes namespace ownership, registry URL,
  and publication signer explicit
- one signed listing envelope shared across current tool-server, credential-
  issuer, credential-verifier, and liability-provider publication flows
- explicit `origin`, `mirror`, and `indexer` publisher roles plus freshness
  windows and a reproducible search-policy contract over generic listing
  reports
- one deterministic generic-registry ranking algorithm,
  `freshness-status-kind-actor-published-at-v1`, that preserves visibility
  ordering without implying trust activation or endorsement
- compatibility references that preserve the underlying certification,
  discovery, or provider-artifact provenance instead of replacing it
- one signed local trust-activation artifact that binds one current listing,
  one local operator decision, one review context, one admission class, and
  bounded eligibility rules into explicit runtime import truth
- four machine-readable admission classes, `public_untrusted`, `reviewable`,
  `bond_backed`, and `role_gated`, that preserve local operator review and do
  not collapse visibility into runtime admission
- one signed governance-charter artifact plus one signed governance-case
  artifact family over that same registry surface, with explicit namespace,
  listing, operator, and activation scope for dispute, freeze, sanction, and
  appeal actions
- one signed federation-activation exchange artifact that carries one local
  trust activation, one listing, one optional governing charter, one bounded
  scope, and one fail-closed import policy across operators
- one signed federation-quorum report over origin, mirror, and indexer
  observations with explicit freshness, conflict, and anti-eclipse evidence
- one signed federation kernel-trust handshake over a `SigningBackend`,
  allowing Ed25519, P-256, P-384, or hybrid PQ signing identities to pin peers
  through the same envelope and verification path
- one signed federated open-admission policy plus one signed federated
  reputation-clearing artifact over stake or bond requirements, local
  weighting, independent-issuer diversity, and corroborated negative events
- one signed federation-qualification matrix that covers hostile publisher,
  conflicting activation, insufficient quorum, eclipse, reputation-sybil, and
  governance-interop cases before Chio claims bounded cross-operator trust
- fail-closed rejection when one namespace resolves to conflicting ownership
  claims or when a projected listing or aggregated replica set is stale,
  divergent, malformed, or otherwise unverifiable
- explicit separation between listing visibility and any later trust-activation
  or admission decision

Federation handshakes bind a `conformance_tier` into the signed challenge.
The receiving kernel stores that tier on the pinned `FederationPeer`, and
`QuorumPolicy.min_tier` rejects peers below the configured floor before the
peer enters a quorum set. Tiers are derived from threat-coverage, mutation-kill,
and Kani trust-boundary harness evidence:

| Tier | Required evidence |
| --- | --- |
| `bronze` | Schema-valid evidence is present, but the peer does not meet Silver. |
| `silver` | Threat coverage >= 90%, mutation kill >= 65%, and Kani harnesses on >= 4 trust-boundary crates. |
| `gold` | Threat coverage = 100%, mutation kill >= 80%, and Kani harnesses on >= 8 trust-boundary crates. |

Cross-surface conformance for T2.1 is mandatory before advertising a Silver or
Gold federation posture. The same negative fixture family must run across MCP
wrapped mode, hosted/native HTTP, and A2A or HTTP edge surfaces, and each
surface must prove deny receipts emit, lineage class is preserved, revocation
propagates, budget enforcement is real, and no adapter bypass can skip
capability, scope, or guard checks.

The current generic registry claim is intentionally bounded:

- local operator publication currently emits `origin`-role reports over
  operator-owned state; mirror/indexer replication and aggregation can now
  participate in one bounded quorum report without claiming permissionless
  federation or automatic trust
- listing visibility does not imply trust import, runtime admission, or market
  activation
- trust activation now supports one explicit cross-operator exchange contract,
  but imported activation remains visibility-only until local review and local
  activation accept it
- governance charters and governance-case evaluation remain operator-scoped
  issue/evaluate flows; federation may reference that state, but it does not
  imply permissionless global arbitration or automatic sanctions across
  operators
- missing, stale, divergent, expired, denied, unsigned, or policy-incompatible
  activation state fails closed
- insufficient quorum, missing origin or indexer observation, stale publisher
  state, excessive upstream hops, or unresolved conflict evidence fail closed
- freeze or sanction cases only block local admission when explicitly enforced
  and bound to current local trust-activation truth
- expired, mismatched, unsupported, or unauthorized governance actions fail
  closed
- federated `bond_backed` participation remains review-visible only until
  separate slashable bond proof is bound through the live economic surface
- shared portable reputation may flow through one bounded clearing contract,
  but local weighting, independent issuers, and corroborated blocking events
  remain mandatory; it is not a universal oracle
- current listings project from local operator state plus bounded federation
  evidence; they are not a permissionless global registry
- adversarial replica visibility does not override local trust policy:
  invalid mirror signatures, divergent freshness, and forged remote
  activation authority remain visible as evidence but fail closed for
  admission, governance, and market-penalty evaluation

### 12.1 Economic simulation qualification artifacts

The `chio.econsim.scenario-result.v1` and
`chio.econsim.qualification-matrix.v1` schemas describe deterministic,
synthetic campaigns against named production economy validators. The v1 matrix
enumerates sybil pricing, bid integrity, credit exposure, oracle divergence,
cumulative approval, and settlement retry classes. Each result binds its seed,
corpus digest, exact assertion scope, and explicit limits.

An econsim matrix is self-signed internal qualification. Its signature binds
the runner's assertion and recorded provenance, but does not independently
prove what executed. Econsim artifacts are not runtime wire messages, external
evidence, underwriting inputs, insurance facts, or capability claims. A
missing production target or unresolved High or Critical finding prevents the
runner from emitting a signed matrix.

## 13. Observability Contract

Production observability is part of the shipped contract.

Stable operator surfaces include:

- trust-control `/health` and `/v1/internal/cluster/status`
- hosted edge `/admin/health`, `/admin/sessions`, and session trust views
- provider-admin registry inspection surfaces
- certification registry status surfaces
- certification marketplace metadata, search, transparency, and dispute
  surfaces
- operator report and shared-evidence analytics
- durable A2A task-registry rejection when follow-up correlation is unsafe
- bounded web3 runtime reports for `chio-link`, `chio-anchor`, and `chio-settle`
  with explicit drift, replay, recovery, and emergency-mode state

Field additions are allowed. Silent fail-open downgrades are not.

For operational guidance, see:

- `docs/release/OBSERVABILITY.md`
- `docs/release/OPERATIONS_RUNBOOK.md`
- `docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md`

## 14. Explicit Gaps

The following are intentionally outside the shipped v1 contract:

- permissionless or auto-trusting public federation or certification
  marketplace semantics
- permissionless mirror/indexer publication as automatic trust, sanction, or
  market-penalty authority
- public federation beyond Chio's documented bounded federation-activation
  exchange, quorum, open-admission, reputation-clearing, and qualification
  surfaces
- portable reputation as a universal trust oracle or automatic cross-issuer
  score
- automatic enterprise identity propagation into every portable artifact
- custom A2A auth schemes beyond the shipped matrix
- full automatic wallet/distribution semantics for passports
- permissionless or arbitrary external capital dispatch beyond the documented
  official web3 lane, or autonomous insurer-rate setting beyond the documented
  autonomous-pricing, capital-pool, rollback, live-capital, reserve-control,
  payout, and settlement surfaces
- performance claims beyond the qualification and documentation surfaces

These gaps are documented explicitly so operators and integrators do not have
to infer them from source code.
