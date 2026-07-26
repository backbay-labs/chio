# Design: aggregate invocation budgets and threshold approvals

- Status: DRAFT (corrected after implementation review)
- Date: 2026-07-09
- Scope: extend the existing capability budget and governed-approval systems; do not add parallel burn, quorum, or proof crates
- Related normative docs: `spec/PROTOCOL.md`, `spec/SECURITY.md`, `docs/security/threat-coverage.md`
- Related implementation plan: `docs/superpowers/plans/2026-07-09-protocol-primitives.md`

## 1. Decision summary

Chio already has spend-bounded capabilities. `ToolGrant.max_invocations` is part of the signed scope, and `chio-kernel` enforces it atomically through `BudgetStore`. The store has in-memory, SQLite, and remote implementations, mutation events, authority leases, hold reversal and reconciliation, and explicit guarantee levels. This design does not replace that machinery.

This arc contains two implementation tracks and one explicit deferral:

1. Add an optional aggregate invocation budget to a capability. The aggregate limit supplements every matching grant's existing `max_invocations`. It can count either one capability token or an entire verified delegation family. Enforcement extends the existing `BudgetStore` hold and event model so per-grant and aggregate admission are one atomic decision.
2. Add threshold governed approval by verifying multiple existing `GovernedApprovalToken` values against the `extensions.chio.human_in_loop.approvers.n/of` policy. The kernel reuses the existing request, intent, subject, time, trust, signature, and replay checks. It does not introduce a weaker signature envelope or a `chio-quorum` crate.
3. Defer general proof-carrying authorization. The proposed Transaction Passport crates do not exist. Phase one continues to accept only Chio's existing runtime-attestation evidence and runtime proof-parity artifacts through their current validators. Those artifacts are evidence inputs, not proofs of authorization.

## 2. Verified current state

| Existing control | Source of truth | Consequence for this design |
|---|---|---|
| Per-grant invocation ceiling | `ToolGrant.max_invocations` in `chio-core-types` and section 5.1 of `spec/PROTOCOL.md` | No `use_limit` field and no separate burn ledger |
| Atomic budget enforcement | `BudgetStore`, `BudgetAuthorizeHoldRequest`, and `BudgetMutationRecord` in `crates/kernel/chio-kernel/src/budget_store.rs` | Extend the hold transaction with aggregate quota keys |
| Durable budget backend | `SqliteBudgetStore` in `crates/platform/chio-store-sqlite/src/budget_store/` | Aggregate limits are not production-ready until this backend is implemented |
| Governed approval artifact | `GovernedApprovalToken` in `crates/core/chio-core-types/src/capability/governance.rs` | Verify a set of existing tokens instead of defining another signature format |
| Governed approval enforcement | `validate_governed_approval_token` in `crates/kernel/chio-kernel/src/kernel/governed_validation.rs` | Factor pure token verification from replay reservation, then apply it to a set |
| Threshold policy shape | `ChioApproverSet { n, of, timeout_seconds }` in `crates/guards/chio-policy/src/models.rs` | Policy, not the caller, determines the threshold and eligible signers |
| Bilateral DSSE | `crates/trust/chio-federation/src/bilateral_dsse.rs` | Preserve the exact-two bilateral profile; share threshold algorithms with a future n-of-m profile |
| Runtime evidence | `RuntimeAttestationEvidence` and `validate_runtime_proof_parity_report` | Reuse existing verification; do not claim general proof-carrying authorization |
| Feature negotiation | `CapabilityNegotiation` in `crates/core/chio-core-types/src/capability/features.rs` | New wire semantics require explicit negotiated feature bits |

## 3. Goals and non-goals

### Goals

- Bound total invocation attempts across all grants in one token when a capability-wide aggregate budget is present.
- Optionally share that aggregate ceiling across descendants of one verified delegation root.
- Preserve the existing per-grant limits and cost-budget semantics. Every applicable limit must admit the request.
- Require `n` distinct, eligible governed approvers for policy-selected operations.
- Make state transitions durable, idempotent, auditable, and explicit about their HA guarantee.
- Carry the new wire shapes through Rust, Python, TypeScript, and Go generation and through every kernel-backed adapter.
- Negotiate new semantics before accepting tokens or requests that rely on them.

### Non-goals

- Do not create `chio-burn`, `chio-quorum`, or `chio-proof-carry`.
- Do not reinterpret or remove `ToolGrant.max_invocations`.
- Do not allow a request to declare its own threshold, eligible signer set, or budget-family identifier.
- Do not make in-memory state the production guarantee.
- Do not treat a signed assertion as a proof that arbitrary policy predicates hold.
- Do not generalize bilateral federation DSSE in the first implementation stage.
- Do not copy Spine code until the AegisNet-derived files have a completed provenance and license audit.

### Cross-arc sequencing

This arc owns the shared authorization authorities used by the sibling security arcs:

- The enterprise hardening broker may enforce destination and credential constraints before this arc lands, but it must not claim a production `max_executions` guarantee with a broker-local counter. A trusted `SupplementalQuotaVerifier` installed by runtime composition verifies the opaque signed broker capability and returns a request-bound broker quota claim without a kernel dependency on `chio-secret-broker`. A broker-mediated invocation contributes that distinct quota to the same authoritative composite hold as the grant and aggregate quotas. Dispatch uses the combined budget-and-revocation capture authority defined below, then captures the already-reserved hold once before the outbound side effect.
- Active-defense heavy actions must use threshold governed approval from this arc. Quarantine, destructive response, and other policy-selected actions may collect approvals earlier, but they must not dispatch through a separate co-signature envelope or replay store. An active response is represented by a typed `GovernedTransactionIntent` response-plan body authorized by a verified Chio operator capability. Approvals bind `GovernedTransactionIntent::binding_hash()`, the threshold proposal binds the operator-capability digest, and replay state is coordinated by a generic approval-only `AdmissionOperation`.
- The dependency direction is one way. This arc defines generic budget and approval contracts and does not depend on enterprise broker or active-defense crates.

## 4. Aggregate invocation budget

### 4.1 Signed token shape

`CapabilityToken::sign` and `sign_with_backend` currently accept `CapabilityTokenBody`. The issuance model must therefore change at that boundary, not only on the serialized token. `CapabilityToken` and `CapabilityTokenBody` gain one optional field. `CapabilityTokenSigningBody` and `CapabilityTokenAttenuationBody` include it through their flattened `CapabilityTokenBody` and must not serialize a duplicate copy.

```rust
pub struct AggregateInvocationBudget {
    pub scope: AggregateInvocationScope,
    pub max_invocations: u32,
    pub root_binding: Option<AggregateBudgetRootBinding>,
}

pub enum AggregateInvocationScope {
    Capability,
    DelegationFamily,
}

pub struct AggregateBudgetRootBindingBody {
    pub schema: String, // chio.aggregate-budget-root.v1
    pub root_capability_id: String,
    pub root_capability_hash: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub max_invocations: u32,
    pub root_expires_at: u64,
    pub root_scope_hash: ScopeHash,
}

pub struct AggregateBudgetRootBinding {
    pub body: AggregateBudgetRootBindingBody,
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}
```

The wire name is `aggregate_invocation_budget`. `CapabilityToken::body()`, every Ed25519, backend, and attenuation sign path, and every issuance constructor copy the field through `CapabilityTokenBody`. The field uses `skip_serializing_if = "Option::is_none"`, so a body with no aggregate budget produces the existing signing bytes. Legacy-body signature fallback is permitted only when this field is absent. `max_invocations = 0` is valid and denies all dispatches under that aggregate scope.

A direct CA issuance of `DelegationFamily` is two-stage and non-circular:

1. Build an `AggregateBudgetRootCommitment` from the would-be direct root body with an empty delegation chain and no root binding. It contains the root ID, issuer, subject, scope hash, issuance and expiry, aggregate scope, and maximum.
2. Compute `root_capability_hash = SHA256("chio.aggregate-budget-root-commitment.v1\0" || canonical_json(commitment))`.
3. Build `AggregateBudgetRootBindingBody` from that commitment and sign `"chio.aggregate-budget-root.v1\0" || canonical_json(binding_body)` with the issuing CA key.
4. Insert the binding into `CapabilityTokenBody.aggregate_invocation_budget`, then sign the complete capability token through the ordinary `CapabilityToken::sign` or `sign_with_backend` path.

The root hash is explicitly the pre-binding root commitment hash, not a hash of the final self-containing token. The binding signature and the final capability signature are separate and both are required.

Delegation evidence identifies the preserved binding with `SHA256("chio.aggregate-budget-root-binding-digest.v1\0" || canonical_json(full_root_binding))`. This digest is audit metadata; the family quota owner remains the separately domain-separated hash of the verified binding body.

The field is not a replacement for grant limits. A request with a matching grant limit of 10 and an aggregate limit of 3 is admitted only while both counters have capacity.

Production authority and HTTP issuance remain disabled until the atomic aggregate quota store and dispatch-capture path are installed. The core signing helper exists for vectors and verifier tests; an authority must not advertise an unenforced ceiling.

### 4.2 Counter ownership

The kernel derives the quota owner after full capability, delegation, and root-binding verification:

- `Capability`: the owner is `CapabilityToken.id`.
- `DelegationFamily`: the owner is `SHA256("chio.aggregate-budget-family-key.v1\0" || canonical_json(verified AggregateBudgetRootBindingBody))`; the root capability ID remains signed display and audit metadata.

The request and delegation links cannot supply or replace the family owner. `delegation_chain.first().capability_id` is not an authenticated family-root assertion by itself and is never used as the quota authority.

The storage key is structured and domain separated:

```text
BudgetQuotaKey {
  profile: "chio.grant-invocation.v1"
         | "chio.aggregate-capability-invocation.v1"
         | "chio.aggregate-family-invocation.v1"
         | "chio.broker-capability-execution.v1",
  owner_id: <derived id>,
  grant_index: <u32 or absent>
}
```

Implementations may encode this structure for a database key, but must not build ambiguous keys by concatenating unescaped user strings.

The broker-capability owner is `SHA256("chio.broker-capability-execution.v1\0" || canonical_json(verified broker capability ID, issuer, destination and request-constraint digest))`. Its immutable maximum comes from the verified broker capability. Caller request fields cannot create the key or maximum.

`chio-kernel` does not parse an enterprise broker type. It owns a `SupplementalQuotaVerifier` port whose trusted implementation is installed by the control-plane composition root. The port receives opaque authenticated extension bytes plus a kernel-built context containing capability id and digest, subject, authenticated request-namespace digest, operation and request IDs, normalized destination, canonical arguments digest, and negotiated features. The arguments digest covers the complete normalized tool arguments that can change outbound bytes or effect semantics; adapters cannot omit method, headers, body, options, or protocol extensions that live in that action. The port returns a `VerifiedSupplementalQuotaClaim` containing the verified broker capability ID, issuer, destination, request-constraint digest, maximum, authorization-artifact digest, revocation IDs, expiry, profile, and exact context bindings. It does not return an authoritative `owner_id`. The kernel accepts this value only as the direct result of its composition-installed verifier, rechecks every context binding, and derives the structured quota key itself from those verified components. The installed verifier identity and configuration digest are composition authority, not self-reported adapter fields, and are bound into the hold. Supplemental authorization with no installed verifier, an unknown profile, or a mismatched binding denies. The enterprise adapter implements the port with the signed broker-capability verifier, so dependencies remain `control-plane -> chio-secret-broker` and `control-plane -> chio-kernel`.

### 4.3 Delegation and attenuation

Aggregate budgets are authority and must be lineage-bound:

- `Capability` scope is valid only when the token does not authorize `Operation::Delegate`. Otherwise a holder could mint fresh capability counters and bypass the ceiling. A delegable aggregate budget must use `DelegationFamily`.
- `Capability` requires `root_binding = None`; `DelegationFamily` requires a verified `root_binding`.
- A v1 `DelegationFamily` originates only on a direct token with an empty delegation chain, issued by a trusted capability authority. A delegated token cannot start a new family.
- The direct root's binding must verify under `root_issuer`, and that issuer must equal the root token issuer. Root ID, pre-binding root hash, subject, maximum, expiry, and root scope hash must match the direct root commitment.
- Every descendant must preserve the exact canonical root binding and the exact family maximum. Omission or any changed byte is rejected. A descendant cannot lower the maximum for the shared row because a quota key has one immutable maximum.
- For a descendant, the first verified delegation link's capability ID, delegator, and scope hash must equal the binding's root capability ID, root subject, and root scope hash. Descendant expiry cannot exceed the bound root expiry. This rejects grafting a valid family binding onto an unrelated delegation chain.
- A parent without a family binding cannot issue a delegated child with `DelegationFamily`. A trusted CA can issue a separate direct root.
- Descendant verification resolves the signed direct-root capability by the first delegation link's capability ID from verifier-owned lineage. The verifier checks that root token's CA signature and trusted issuer before comparing its aggregate state with the descendant. A missing root snapshot denies. A delegation link or receipt signed only by the root subject cannot prove that a family budget was not omitted at the first hop.
- A capability-scoped limit covers only that nondelegable token. Issuers that need a ceiling over descendants must use `DelegationFamily`.
- Every signed delegation link, attenuation witness, and delegation receipt records preservation of the root-binding digest and family maximum. These projections detect mutation between known ancestors, but they supplement rather than replace the authenticated direct-root lookup.
- Portable full-verification entry points receive an authenticated direct-root snapshot or a trusted resolver. Negotiated aggregate semantics with no such root evidence deny instead of treating an absent leaf field as an unbudgeted family.
- Portable v1 verification rejects aggregate or cumulative family descendants with more than one delegation link. A direct-root and final-leaf envelope cannot prove an intermediate capability's child scope or issuance chronology. Multi-hop portable support requires authenticated per-hop child-scope witnesses before it can be enabled.

Verifier-owned lineage persists the complete signed capability token alongside its scalar audit projection. The signed token is nullable only for pre-migration rows and explicit non-capability federation anchors; every newly recorded real capability preserves its exact token. Synthetic federation relationships live in the separate lineage-bridge projection and never rewrite signed token lineage. Replication, evidence export, and portable verification preserve the exact token; no verifier reconstructs it from capability ID, keys, scope JSON, or timestamps. When either aggregate invocation or cumulative approval semantics are negotiated, every delegated token requires the signed direct root identified by its first verified delegation link. A legacy row or synthetic anchor with no signed token denies on those paths.

### 4.3.1 Cumulative approval authority

The `cumulative_approval_budget` feature introduces the strict `RequireCumulativeApprovalAbove` variant. Its threshold is a `MonetaryAmount`, and its signed budget ID, epoch, currency, and optional family-root binding are authority. The legacy `RequireApprovalAbove { threshold_units }` variant remains per-request behavior and never advertises cumulative enforcement.

A nondelegable direct capability carries no family-root binding and derives its cumulative account from the verified capability issuer and capability ID. A delegable root carries a CA-signed, domain-separated `CumulativeApprovalRootBinding` over the pre-binding root commitment, root issuer and subject, root scope and grant identity, approval budget ID and epoch, currency, root threshold, and expiry. Descendants preserve the binding's canonical bytes, budget ID, epoch, and currency. A descendant may lower the approval threshold or expiry, but cannot raise either above the authenticated root authority, create a cumulative family below an unbound root, or omit the binding.

The family owner is derived only after verifying the direct root token, root binding, and delegation origin. Delegation links and attenuation witnesses carry preservation markers as mutation evidence, but do not replace the signed direct-root lookup. Feature-disabled verifiers reject the cumulative form rather than interpreting it as the legacy per-request threshold.

The shared cumulative account stores the immutable root authority threshold. Each
operation reservation stores the verified effective leaf threshold and compares
the prospective shared total against that value. Lowering a descendant threshold
therefore cannot reset the family accumulator or silently tighten a sibling's
policy. A direct nondelegable constraint uses the same value for both thresholds.

Until a joint aggregate-and-cumulative pre-binding commitment is defined, v1 rejects every capability that combines `aggregate_invocation_budget` with `RequireCumulativeApprovalAbove`; the independent signing helpers cannot be composed into ambiguous roots.

### 4.4 Atomic store contract

`BudgetStore` remains the single budget authority. `BudgetAuthorizeHoldRequest` is extended to carry a bounded, sorted set of invocation quota claims. `MAX_INVOCATION_QUOTAS_PER_ADMISSION` is 8 in v1. Revocation IDs are ordered by their UTF-8 bytes before canonical JSON hashing. A broker-mediated call normally contributes three distinct claims: the matched grant quota, the parent capability or family aggregate quota, and the supplemental broker-capability quota. Its hold also binds the composition-supplied verifier identity and configuration digest, exact authorization-artifact digest, and exclusive artifact expiry. Capture rechecks that expiry against trusted capture time. The backend must perform one compare-and-mutate transaction:

1. Load every quota row in a deterministic key order.
2. Verify the maximum recorded for an existing key equals the presented signed maximum. A key's maximum is immutable; mismatch is an invariant failure.
3. Verify each committed count plus live reservations is below its maximum.
4. On any exhausted quota, record one denied mutation, change no usage row, and
   create no absent quota or cumulative-account row. A denial does not define an
   immutable maximum for a key that has never been authorized.
5. On success, create one idempotent hold covering every quota key.
6. Return the post-admission counts and `BudgetCommitMetadata` from the same commit.

Structured durable authorization, invocation capture, and captured-invocation
cancellation require nonempty paired `hold_id` and `event_id` values. Legacy
rich mutation entry points retain compatibility with requests that omit both
identifiers or provide only a nonempty event ID. They reject empty identifiers
and any hold ID without an event ID. An exact stored event replays only when all
request inputs match. A different event against a superseded hold state, an
event reused with different inputs, or a replay after a later terminal
transition fails closed.

The existing `try_increment` entry point remains a compatibility wrapper over
the same transaction with one grant quota. It must not become a second authority
path. Its unheld compatibility accounting tracks reversible invocations per
capability and grant rather than per exact exposure amount. A partial monetary
release leaves that count available; full reversal or settlement consumes one.

The extension covers the complete existing lifecycle: `authorize_budget_hold`, `reverse_budget_hold`, `release_budget_hold`, `reconcile_budget_hold`, and `capture_budget_hold`, plus an explicit invocation-capture transition. Aggregate and broker quota membership and authority metadata must survive every transition. No caller, including the enterprise broker, may implement execution reservation by calling `try_increment` and then performing side effects outside the hold lifecycle.

Invocation reservation and monetary exposure are orthogonal substates of one hold:

```text
invocation: absent | authorized | captured | reversed | denied
monetary:   none   | exposed    | released | reconciled | captured | reversed
```

`capture_invocation_reservations` consumes every invocation quota at dispatch
commitment. A hold authorized with positive monetary exposure must remain
`Exposed` with positive remaining exposure through invocation capture. Partial
pre-dispatch release may leave it `Exposed`; full release makes invocation
capture fail closed. Existing `capture_budget_hold`, `release_budget_hold`, and
`reconcile_budget_hold` continue to describe monetary exposure and spend.
`reverse_budget_hold` may reverse still-authorized invocation reservations and
monetary exposure only while dispatch is proven not to have begun. After
invocation capture, exposed money may only capture or reconcile; a generic
release cannot cross the dispatch commitment fence. The only v1 compatibility
exception is the explicit pre-dispatch cancellation for a legacy synthesized
single-grant hold, which reverses its captured grant quota and exposure together.
Explicit composite or cumulative captures are terminal and cannot use that
exception. Invocation `captured` or `reversed` is terminal for the invocation
substate, but the whole hold is not terminal while permitted monetary capture or
reconciliation remains.

A cumulative operation at or above its effective threshold remains
`PendingApproval` until one compare-and-swap transition wins. Verified approval
attachment expects `PendingApproval` and advances it to `Authorized`. Timeout
reversal also expects `PendingApproval` and advances it to
`ReversedBeforeDispatch`. If they race, exactly one succeeds and the other fails
closed against the changed state.

Rich terminal `BudgetStore` transition defaults fail closed. A backend implements
rich reverse, release, reconciliation, or monetary capture only when it can
return the truthful event-time quota, invocation, monetary, cumulative,
authority, and commit projection. A default never fabricates empty state and one
transition is never aliased to another. The unstructured single-grant
authorization default remains a compatibility adapter; production backends
override it to return an atomic event-time projection.

Strict execution-nonce preflight authorizes a bounded grant through a separate
deterministic `nonce-preflight-budget-hold:{request_id}:{capability_id}:{grant}`
namespace and event `{hold_id}:authorize`. Cleanup derives its rollback event
from that authorization event and commit index. Authorization and compensation
remain append-only terminal records. A lost cleanup acknowledgement may retry the
exact rollback event, but a repeated nonce-free request cannot mint another
nonce. The nonce-bearing execution uses a separate executable hold and cannot
reopen the preflight hold.

In v1, a broker quota supplements one kernel invocation. Trusted broker preverification contributes `chio.broker-capability-execution.v1` to the kernel's composite hold. The broker does not reserve another quota at its outbound boundary; it captures the already-authorized invocation reservations once, immediately before sending the upstream request. Standalone broker execution without a kernel `AdmissionOperation` and the combined capture authority cannot claim production `max_executions` enforcement.

SQLite uses one `BEGIN IMMEDIATE` transaction with unique `event_id` and `hold_id` constraints. Remote budget service calls must provide a linearizable commit index for a hard aggregate limit. `AdvisoryPosthoc` is never sufficient. `PartitionEscrowed` is acceptable only when the receipt states the escrow allocation and the sum of allocations cannot exceed the signed maximum.

### 4.5 Revocation-linearized capture

A signed freshness snapshot from an independent revocation store is not atomic with budget capture. Production broker dispatch therefore uses one `AdmissionCaptureAuthority` that serializes relevant revocation writes and invocation capture in the same linearizable commit domain. During capability verification the kernel derives a canonical sorted revocation set containing the leaf capability id, every delegation-chain ancestor capability id checked by validation, and every supplemental authorization revocation id. The hold and `AdmissionOperation` bind the digest of that complete set. Capture receives the operation and hold ids, complete set and digest, verified authorization-artifact digests, and last observed revocation index. In one commit it reads latest state for every bound id, denies any revoked, omitted, added, or mismatched authorization, captures every invocation quota exactly once, and returns signed `AdmissionCaptureMetadata` carrying the checked-set digest plus budget and revocation indices from that commit.

For single-node storage, `SqliteAdmissionCaptureAuthority` owns budget and revocation tables in one SQLite database and one `BEGIN IMMEDIATE` transaction. All revocation writes for capabilities eligible for combined capture must use that authority; a separate writer is a startup error. For HA, the remote trust-control service applies revocation mutations and captures through one consensus log and leader epoch. Merely calling `RevocationStore::is_revoked` before `BudgetStore::capture_invocation_reservations` does not satisfy this contract. If a deployment cannot supply the combined authority, broker dispatch fails closed. Revocation committed after capture is ordered after the admitted dispatch and cannot make the earlier capture reusable.

### 4.6 Validation and consumption ordering

State must not be consumed merely because an attacker submitted malformed authorization material. One durable `AdmissionOperation` coordinates the authorities.
RFC-0003 and the 2026-07-12 admission-operation correction extend this same
coordinator to every configured monetary or side-effecting tool call, including
calls without aggregate, broker, or threshold admission. They do not add a
second dispatch-intent coordinator:

```text
AdmissionOperationV1 {
  kind,
  operation_id,
  coordinator_authority_id,
  request_namespace_digest,
  request_id,
  capability_id,
  authorization_capability_hash,
  request_binding_hash,
  policy_hash,
  effect_class,
  threshold_proposal_hash?,
  supplemental_authorization_digest?,
  broker_attempt_id?,
  budget_hold_id?,
  approval_set_hash?,
  execution_nonce_id?,
  outcome_eligibility_digest?,
  tool_outcome_id?,
  terminal_result_id?,
  terminal_result_digest?,
  state,
  dispatch_state,
  coordinator_lease_epoch,
  version,
  last_error?,
  terminal_receipt_id?,
  terminal_incident_id?,
}
```

This `AdmissionOperationV1` field set is the one owned canonical schema used by
the design, executable plan, RFC-0003 and extensions. Nullable late-binding
fields compare-and-swap from null once; terminal receipt, incident, and mutation
result references are mutually exclusive. An extension may add a typed field only through a versioned
schema change, not an incompatible shadow struct.

`AdmissionOperationKind` is `ToolDispatch`, `GovernedActiveResponse`, or
`GovernedEconomicMutation`. The last kind covers an authority-mediated durable
state mutation such as WS2 direct assignment without pretending it is a tool
dispatch or creating another coordinator. `operation_id` is `SHA256("chio.admission-operation.v1\0" || canonical_json({ kind, coordinator_authority_id, request_namespace_digest, request_id, capability_id, authorization_capability_hash, request_binding_hash }))`. The authenticated namespace is part of the global primary-key identity as well as the replay unique key. `request_binding_hash` covers only immutable normalized request fields that can change the governed effect: arguments or response plan, governed intent, policy requirements, destination, pricing selection, and settlement mode. It deliberately excludes the authority-generated threshold proposal, approval-set membership, supplemental authorization artifacts, execution nonce references, and other evidence learned or supplied after the operation is persisted. The proposal hash and verified participant bindings are compare-and-swap attached to their nullable operation fields exactly once before `ReadyToDispatch`, then become immutable. A retry may therefore add required evidence to the same operation, but cannot change the request, swap an attached proposal or approval set, or derive a second identity by reordering tokens.

The operation is persisted before the first authoritative mutation. Budget,
payment, approval replay, nonce, provider acceptance, and broker-attempt
participants receive the same `operation_id` as their idempotency and ownership
key. State advances use compare-and-swap on `version` under a fenced coordinator
lease so an executor and recovery worker cannot both commit dispatch. The
coordinator records each transition after the participant acknowledges it. If a
crash occurs between a participant commit and the coordinator update, recovery
queries that participant by `operation_id` and advances the saga without
repeating a side effect. Missing operation storage denies before any reservation.

The kernel order is:

1. Parse with size and count limits.
2. Validate token schema, signature, issuer trust, time, revocation, DPoP, delegation chain, and attenuation.
3. Resolve the matching grants, derive the aggregate quota key, and build the canonical revocation set from the leaf and every verified delegation ancestor. If supplemental authorization is present, invoke the installed verifier, recheck its capability, subject, request, destination, expiry, and negotiation bindings, add all verified supplemental revocation ids, and bind the final set digest into the hold and operation before deriving its quota key.
4. Load by authenticated `(request_namespace_digest, request_id)`. For an
   existing operation, verify the immutable request against its stored binding.
   For a fresh request, verify governed intent and runtime evidence, evaluate
   policy, run pre-invocation guards and runtime admission, and persist
   `AdmissionOperationV1::Prepared` before any authority reservation.
5. Verify any presented approval signatures against that stored proposal without
   mutating replay or budget state. On retry, compare-and-swap each verified
   supplemental authorization, approval-set, or nonce binding from null exactly
   once; reject a mismatch with an existing binding.
6. For broker dispatch, call authenticated local `RegisterAttempt` with deterministic operation, attempt, hold, event, proof, and request digests. The broker validates non-secret request constraints, persists and fsyncs its pending intent, and returns an idempotent acknowledgement. This control IPC is not upstream execution and cannot materialize or transmit a credential. Persist `BrokerAttemptRegistered`. A failure consumes no budget.
7. In one `BudgetStore` call, atomically reserve the cumulative-approval participant and the bounded grant, aggregate, broker, and monetary claims under `operation_id`. The durable cumulative result supplies the authoritative `reserved_at`, effective threshold, and budget epoch. Below the threshold the cumulative substate is `Authorized`; at or above it the substate is `PendingApproval` and invocation capture is forbidden.
8. For `PendingApproval`, CAS-attach the exact authority-signed proposal and persist operation-local `ApprovalRequired`, then return it. A crash between the composite reservation and proposal attachment queries the hold by operation ID and derives the same proposal from that durable result. On retry, attach the verified approval set through a separate CAS that advances the existing cumulative substate to `Authorized`; never mutate or repeat the authorize request.
9. Persist `BudgetAuthorized`, reserve the approval set under `operation_id`, and persist `ApprovalReserved`.
10. Reserve the execution nonce under `operation_id`; persist `ReadyToDispatch`. The broker may now materialize and prepare the credentialed request but still cannot send it upstream.
11. Persist `CapturePending`, then commit the approval and nonce reservations. Ordinary dispatch captures invocation reservations through the budget authority. Broker dispatch calls `AdmissionCaptureAuthority`, which rechecks the leaf, every delegation ancestor, and every supplemental revocation id and captures all invocation quotas in one linearizable commit. A denial compensates the still-authorized hold and tells the broker to terminate the pending attempt; approval and nonce tombstones remain consumed.
12. After successful capture, persist `DispatchCommitted` and only then authorize the broker's upstream send or begin the ordinary tool-server side effect. A crash after capture but before this state write is recoverable by querying capture under `operation_id`, because code cannot send before the write. Once `DispatchCommitted` is durable, recovery does not resend without downstream idempotency and invocation quotas remain consumed even if the process crashed before the actual send or the response was lost.
13. Release, capture, or reconcile monetary exposure independently when the
outcome becomes known. Persist the exact settle action before a rail call. Then
use RFC-0003's composable receipt-side transaction to append the receipt, retain
the terminal operation, and apply every required local projection. Cross-database
payment state remains an idempotent saga participant and is not part of that
atomicity claim.

Approval and nonce reservations use `reserved`, `committed`, and `cancelled` records. Compensation before dispatch reverses the budget hold and marks approval and nonce reservations cancelled, but retains replay tombstones. It never makes an approval token or nonce reusable. Compensation is idempotent by `operation_id`. After `DispatchCommitted`, recovery never reverses invocation quotas or automatically releases a monetary hold and never resends unless the downstream protocol proves the same operation ID is idempotent. `Completed`, `CompensatedBeforeDispatch`, `NotAcceptedAfterDispatchCommit`, and `OutcomeUnknownAfterDispatch` remain tool-dispatch replay tombstones; `EconomicMutationApplied` and `EconomicMutationNotApplied` are retained mutation tombstones. Receipt success never deletes the operation.

This is a persisted saga, not a claimed cross-database transaction. Required tool recovery outcomes are `Completed`, `CompensatedBeforeDispatch`, `NotAcceptedAfterDispatchCommit`, or `OutcomeUnknownAfterDispatch`; governed mutation recovery ends in `EconomicMutationApplied` or `EconomicMutationNotApplied`. Every crash point before and after each authority call and each saga-state write is tested.

This preserves preverification before authoritative admission and avoids both free side-effect retries and budget exhaustion by invalid signatures.

For `GovernedActiveResponse`, the verified operator capability occupies `capability_id` and `authorization_capability_hash`; budget, capture, and nonce participants are absent. After committing the approval reservation, the coordinator persists `DispatchCommitted` before any response effect. Effect ids are independently idempotent, so recovery resumes the same plan rather than creating a second admission. The control-plane exposes this through a trusted port to the active-defense executor rather than adding a `chio-quarantine -> chio-kernel` dependency.

For `GovernedEconomicMutation`, the authoritative mutation service receives
`operation_id` as its idempotency key. Its own transaction compare-and-swaps the
resource version/fence and retains a versioned signed applied or
permanently-not-applied result. It does not mark a separately stored local
operation terminal. The admission coordinator looks up and private-verifies that
result, then commits `EconomicMutationApplied` or
`EconomicMutationNotApplied` through the local terminal projection, binding the
canonical result id/digest plus audit event. Recovery repeats lookup, never the
mutation, and makes no cross-store atomicity claim or workstream-local
coordinator.

### 4.7 Receipt projection

Do not add a free-standing `Burn` receipt. The authoritative `ChioReceipt.metadata.budget_authority` projection gains:

- each structured quota key and signed maximum
- count before and after
- hold and event IDs
- invocation and monetary substate transitions
- authority lease, guarantee level, and commit index
- verified root-binding digest and root capability ID when applicable
- supplemental broker-capability quota when applicable
- supplemental-verifier identity and verified authorization-artifact digest when applicable
- combined budget and revocation commit indices and leader epoch for broker capture
- complete checked revocation-set digest for broker capture
- `AdmissionOperation.operation_id`, saga state, and dispatch state

The metadata is part of the signed receipt body. A denial caused by exhaustion records the exhausted dimension without leaking unrelated quota owners.

## 5. Threshold governed approval

### 5.1 Policy is authoritative

`extensions.chio.human_in_loop.approvers` already expresses `n`, `of`, and `timeout_seconds`. Policy loading compiles it to a kernel-owned requirement:

```text
ThresholdApprovalRequirement {
  required: n,
  eligible: sorted map of approver id to public key,
  proposal_timeout_seconds,
  eligible_set_digest,
  policy_hash,
}
```

Policy load fails when `n == 0`, `n > of.len()`, an approver is duplicated, a key cannot be resolved, or the timeout exceeds the governed-approval maximum. `timeout_seconds = None` means the exact default `DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS = 900`. The hard maximum is 3600 seconds. The caller never supplies or weakens this requirement.

The eligible-set digest is `SHA256("chio.approver-set.v1\0" || canonical_json(sorted approver IDs and public keys))`. It changes when an identifier or key changes; threshold and policy hash remain separate fields in every proposal and verified-set binding.

### 5.2 Request shape and compatibility

`ToolCallRequest` gains `approval_tokens: Vec<GovernedApprovalToken>` and an optional signed threshold proposal. During one compatibility window, the existing singular `approval_token` is accepted as a one-element set. Supplying both token forms is rejected as ambiguous. Once all adapters migrate, the singular field can be removed before the public v1 freeze.

Threshold approval uses a policy-authority-signed proposal:

```text
ThresholdApprovalProposalBody {
  schema: "chio.threshold-approval-proposal.v1",
  proposal_id,
  request_id,
  governed_intent_hash,
  subject,
  authorization_capability_hash,
  policy_hash,
  required,
  eligible_set_digest,
  proposal_created_at,
  proposal_deadline,
}
```

`proposal_created_at` comes from the trusted collector or coordinator clock when the proposal is durably created. `proposal_deadline` is exclusive and equals `min(proposal_created_at + policy timeout, authorizing capability expiry, governed operation expiry)`, using checked arithmetic. `authorization_capability_hash` is the canonical digest of the already verified tool or operator capability and is part of the signed proposal. The signed proposal is verified against the current policy authority. Direct callers that bypass the durable collector must still present this signed proposal; caller-supplied timestamps alone have no authority.

`GovernedApprovalTokenBody` gains an optional signed `threshold_proposal_hash`. It is required for threshold tokens and equals `SHA256("chio.threshold-approval-proposal.v1\0" || canonical_json(proposal_body))`. Legacy one-of-one approvals may omit it during the compatibility window.

Input limits are normative: no more than the policy's eligible signer count, with a deployment ceiling of 32 tokens. Oversized sets fail before signature verification.

### 5.3 Verification contract

The existing governed-token verifier is split into a pure check and an authoritative replay reservation. The pure set verifier:

1. Recomputes `GovernedTransactionIntent::binding_hash()` from the canonical typed intent.
2. Verifies the threshold proposal signature, current policy hash, threshold, eligible-set digest, request ID, intent hash, subject, authorizing-capability digest and expiry bound, and governed-operation expiry bound.
3. Requires `proposal_created_at <= now < proposal_deadline` and rejects a future, expired, overflowed, or overlong proposal.
4. Requires every token to bind the exact proposal hash, `request_id`, intent hash, and capability subject.
5. Requires every token's `issued_at` to be within `[proposal_created_at, proposal_deadline)` and `expires_at <= proposal_deadline`.
6. Requires `Approved`, an allowed algorithm, a valid signature, and an approver in the compiled eligible set.
7. Requires distinct token IDs, exact canonical token digests, and distinct approver public-key fingerprints.
8. Counts one vote per eligible approver and requires at least `n`.
9. Produces a domain-separated `approval_set_hash` from `VerifiedApprovalSetBody`.

```text
VerifiedApprovalSetBody {
  schema: "chio.verified-approval-set.v1",
  canonical_token_digests: sorted Vec<SHA256>,
  policy_hash,
  required,
  eligible_set_digest,
  request_id,
  governed_intent_hash,
  subject,
  authorization_capability_hash,
  proposal_id,
  threshold_proposal_hash,
  proposal_created_at,
  proposal_deadline,
}
```

Each token digest is `SHA256("chio.governed-approval-token.v1\0" || canonical_json(complete token including signature))`. The final set hash is `SHA256("chio.verified-approval-set.v1\0" || canonical_json(verified_set_body))`. IDs and signer fingerprints remain receipt metadata but are not the hash preimage by themselves.

Duplicate signers are rejected, not counted twice. Extra invalid or ineligible tokens reject the request. Verification is independent of input ordering.

Replay protection reserves the `approval_set_hash`, canonical token digests, and member token IDs atomically under `AdmissionOperation.operation_id`. A previously reserved or consumed token cannot be combined into a new set. Store unavailability denies. Cancelled reservations retain tombstones through `proposal_deadline` so compensation cannot make an approval reusable.

### 5.4 Durable witness collection

Collection stays outside the kernel TCB. Extend the existing approval store with the signed proposal body and a durable row keyed by proposal ID, request ID, and canonical intent hash. Approvals are appended transactionally with unique `(proposal_id, approver_fingerprint)` and `(proposal_id, canonical_token_digest)` constraints. The submitter cannot count as an approver when policy requires separation of duties. Stale policy hashes, changed intents, expired proposals, deadline mismatches, and duplicate approvers fail closed.

The collector returns existing `GovernedApprovalToken` values. It does not mint a summary signature the kernel must trust. The kernel verifies every satisfying token itself.

### 5.5 Active-response intent binding

Heavy active-defense actions use a typed governed intent body, not an arbitrary hash substitution. Evolve `GovernedTransactionIntent` to normalize one of:

```text
GovernedTransactionIntentBody::ToolInvocation(...existing governed fields...)
GovernedTransactionIntentBody::ActiveResponsePlan(GovernedResponsePlanIntentBody {
  plan_schema,
  plan_id,
  operator_capability_id,
  operator_capability_hash,
  operator_capability_expires_at,
  executor_subject,
  canonical_plan_body,
  plan_body_hash,
  target_binding,
  ordered_effects,
  expires_at,
  rollback_binding,
})
```

The active-defense plan type converts to the protocol-owned response-plan body without introducing a core-to-active-defense dependency. The operator capability is verified for issuer trust, subject, time, and revocation before proposal creation and again before apply. Its existing tool grants on internal server `chio.control-plane.active-response` must cover every closed response-effect tool name in the intent, so no new caller-selected action-scope representation is introduced. Validation recomputes `plan_body_hash` from `canonical_plan_body` and rejects a mismatch. `GovernedTransactionIntent::binding_hash()` covers the complete normalized response-plan body and its checked hash. Every approval token then carries that computed governed intent hash, and the signed threshold proposal carries the same operator-capability digest. Code must never place a standalone `plan_hash` directly into `GovernedApprovalToken.governed_intent_hash`.

### 5.6 Federation DSSE

The current bilateral profile requires exactly two known kernel signatures and remains unchanged. A later cross-organization threshold profile may reuse DSSE PAE, canonical predicates, key IDs, and signature verification from `bilateral_dsse.rs`, but it needs a distinct predicate type and negotiated feature. Shared threshold code should accept an eligible-key map and required count; it must not weaken the exact-two bilateral verifier.

## 6. Runtime evidence, not proof-carrying authorization

Phase one adds no proof envelope and no proof caveat. `GovernedTransactionIntent.runtime_attestation` continues through the existing local attestation trust policy and freshness checks. Runtime proof-parity reports continue through `validate_runtime_proof_parity_report` and are accepted only in paths that already establish their provenance.

If a future request carries parity evidence, the artifact must be wrapped in an existing signed export envelope and bind at least the request ID, run ID, verifier identity, static and runtime package hashes, generation time, and expiry. The kernel must verify the trusted signer and require `accepted == true` with no mismatches. Until that complete binding exists, parity reports are operational evidence and do not authorize a tool call.

General proof-carrying authorization remains blocked on a real Transaction Passport contract that defines evidence graph membership, trusted verifier policy, freshness, revocation, request binding, policy-version binding, and runtime parity. Naming a signed claim `ProofEnvelope` does not satisfy that contract.

## 7. Schemas, code generation, and adapters

The source schemas under `spec/schemas/chio-wire/v1/` are authoritative. The implementation updates every duplicated capability-token shape, the opaque supplemental-authorization carrier, agent tool-call request, kernel capability-list projections, governed approval tokens, threshold proposals, verified approval-set bodies, active-response governed intent bodies, and combined capture metadata. The signed `chio.aggregate-budget-root.v1` and `chio.threshold-approval-proposal.v1` artifacts are added to `spec/schemas/registry.json` and the runtime known-schema set.

Run all four generators and commit their output:

```bash
cargo xtask codegen rust
cargo xtask codegen --lang python
cargo xtask codegen --lang ts
cargo xtask codegen --lang go
make codegen-check
```

Kernel-backed MCP, A2A, ACP-Client, OpenAI, and Tower paths must preserve the exact aggregate root binding, opaque signed supplemental authorization, signed threshold proposal, authorizing-capability digest, approval token set, and typed governed intent. An adapter that cannot represent these fields must reject the operation or use an authenticated Chio extension envelope. It must never construct a quota claim, silently drop approvals, reconstruct a root binding, or downgrade to one signer.

## 8. Negotiation and rollout

Add string-keyed features to `CapabilityNegotiation`:

- `aggregate_invocation_budget`
- `threshold_governed_approvals`
- `governed_active_response_plan`
- `threshold_dsse_invocation` only when the later DSSE profile ships

A verifier that sees a token or request using a feature not present in the negotiated intersection rejects it. Missing flags never mean ignore the field. Local deployments use the same profile checks as federation, browser, mobile, FFI, and adapter entry points.

Rollout order:

1. Ship readers, validators, storage migrations, and feature flags with emission disabled.
2. Deploy linearizable aggregate-budget storage, combined budget-and-revocation capture, threshold replay and nonce reservation states, and the durable `AdmissionOperationStore`.
3. Enable issuance and collection for selected policies.
4. Enable adapter emission only after cross-language conformance passes.
5. Remove singular approval compatibility before public v1 if ecosystem migration is complete.

## 9. Conformance and security evidence

Required conformance classes:

- existing per-grant limit remains exact
- aggregate capability exhaustion across different grants
- delegation-family exhaustion across siblings and multiple kernels with one verified CA root binding
- forged or changed root ID, commitment hash, issuer, subject, maximum, expiry, scope hash, and signature deny
- atomic denial across grant, aggregate, broker, and monetary claims
- supplemental verifier absence, context mismatch, expiry, and caller-built claim deny before reservation
- immutable maximum mismatch for an existing quota key denies
- revocation and broker capture have one observable linearization order in the combined authority
- leaf, every delegation ancestor, and every supplemental revocation id are bound to the hold and rechecked at combined capture
- idempotent retry by event ID
- invocation capture remains independent from monetary release, capture, and reconciliation
- `AdmissionOperation` recovery is deterministic at every authority commit and saga-state write
- broker attempt registration and proof-nonce consumption precede budget mutation and recover idempotently
- invalid approval signatures consume no budget or replay state
- duplicate signers or token digests, token reuse, stale policy, wrong subject, wrong request, and wrong intent deny
- proposal time-window, deadline, eligible-set digest, authorizing-capability digest, and active-response plan bindings deny on any mismatch
- approval-only active-response admission recovers without budget or nonce participants and cannot apply twice
- threshold result is invariant under token ordering
- unnegotiated fields deny across native, browser, mobile, FFI, MCP, A2A, and ACP-Client paths
- Rust, Python, TypeScript, and Go fixtures round-trip byte-compatible canonical artifacts

Formal targets are limited and useful: monotonic captured counts, all-or-nothing multi-key admission, immutable quota maxima, family-binding preservation, threshold distinctness, and replay-set uniqueness. Kani harnesses are registered in both `formal/rust-verification/kani-public-harnesses.toml` and `.kani/harnesses.toml`, mapped in `formal/MAPPING.md`, and run through `scripts/run-kani-manifest.sh`. Loom tests use the existing `crates/kernel/chio-kernel/tests/loom_concurrency.rs` and a checked-in script invoked by PR CI. Release gates execute both. Grep-only gates are not security evidence.

## 10. Adapted Clawdstrike inputs and provenance boundary

Clawdstrike is an algorithm and test source, not an alternate authority implementation:

- Adapt durable proposal transaction invariants from `crates/services/control-api/src/routes/policies/proposals.rs` and `crates/services/control-api/migrations/021_policy_proposals.sql`: row locking, distinct approvers, submitter separation, stale-base rejection, and atomic status changes.
- Adapt witness collection and ordering tests from Clawdstrike's checkpoint and marketplace witness surfaces. Chio still verifies `GovernedApprovalToken` values with Chio canonical JSON and trusted keys.
- Adapt composite quota-key and restart-test ideas from broker constraints and posture budgets. Chio uses `BudgetQuotaKey`, `BudgetStore`, and Chio authority metadata rather than Clawdstrike's execution counter.
- Adapt posture persistence test patterns from `crates/services/hushd/src/session/mod.rs`: serialize, restart, restore, reject malformed state, and continue monotonically.

Do not copy Clawdstrike's broker `max_executions` check as the budget authority. Its read-then-execute flow is not an atomic multi-kernel spend primitive. Do not copy plain `serde_json::to_vec` signing where Chio requires RFC 8785 canonical JSON.

Several Spine files state that they were adapted from AegisNet. No Spine implementation may be copied verbatim until the original source, license, attribution, and modification obligations are audited and recorded. A clean-room implementation from Chio's normative contract remains allowed.

## 11. Residual risks and open decisions

- A hard family-wide ceiling requires `SingleNodeAtomic`, `HaLinearizable`, or correctly bounded `PartitionEscrowed` authority. Advisory replication cannot make that claim.
- Budget, approval replay, and nonce stores are separate authorities today. `AdmissionOperation` is the durable saga authority for their ordering and recovery; it does not make them transactionally atomic. Every participant must support lookup and idempotent mutation by operation ID. Broker revocation is different: it must share one linearizable commit domain with invocation capture rather than rely on saga ordering.
- `SupplementalQuotaVerifier` is a trusted composition port. A malicious implementation can manufacture quota authority, so deployments must pin its implementation identity and configuration in the runtime evidence and receipt path.
- A local SQLite operation store is a single-node authority. Multi-worker dispatch requires a shared linearizable saga store and fenced coordinator lease; otherwise startup fails closed.
- `ChioApproverSet.of` currently stores strings. Production threshold policy needs an authenticated, versioned mapping from those IDs to public keys.
- Capturing at dispatch commitment intentionally charges uncertain executions. This is conservative for security but may require operator reconciliation for tool-server failures.
- A general n-of-m DSSE profile has interoperability value but is not required to ship local governed threshold approval.
- Proof-carrying authorization stays deferred until its evidence graph and verifier contract exist in the repository.
