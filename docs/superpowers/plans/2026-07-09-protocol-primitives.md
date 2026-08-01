# Aggregate Invocation Budgets and Threshold Approvals Implementation Plan

> Implement in order. Do not begin a later phase while an earlier phase's acceptance gate is red.

**Goal:** Add an optional capability-wide or delegation-family invocation ceiling and policy-driven n-of-m governed approval by extending Chio's existing budget, approval, schema, adapter, and receipt systems.

**Architecture:** `ToolGrant.max_invocations` and `BudgetStore` remain authoritative for per-grant spending. An optional signed `aggregate_invocation_budget` contributes a second structured quota to the same atomic budget hold. Threshold approval verifies a bounded set of existing `GovernedApprovalToken` values against a compiled HushSpec approver requirement. General proof-carrying authorization is deferred; existing runtime-attestation and proof-parity validation remain the only runtime-evidence path.

**No new crates:** Do not create `chio-burn`, `chio-quorum`, or `chio-proof-carry`.

## Global constraints

- No em dashes in code, comments, or documentation.
- Fail closed on unknown schemas, unnegotiated features, missing stores, stale evidence, unresolved approvers, ambiguous request fields, arithmetic overflow, and partial multi-key mutations.
- Use RFC 8785 canonical JSON for every signed Chio artifact.
- Preserve existing `ToolGrant.max_invocations`, cost holds, authority leases, guarantee levels, and mutation history.
- The caller cannot choose its delegation-family root, approval threshold, or eligible approvers.
- In-memory stores are test and single-process implementations. They are not evidence of HA correctness.
- No `unwrap`, `expect`, or `unsafe` in production code.
- Keep the kernel independent of `chio-policy`. Put shared requirement types in `chio-core-types` or `chio-kernel`; compile HushSpec into those types from the existing higher-level dependency direction.
- Every state mutation has an idempotency key and a signed receipt projection.
- Behavioral tests are required. Grep-only release checks do not satisfy a security gate.

## Existing contracts that must remain green

- `ToolGrant.max_invocations`: `crates/core/chio-core-types/src/capability/scope.rs`
- Budget authority: `crates/kernel/chio-kernel/src/budget_store.rs`
- Kernel budget ordering and cleanup: `crates/kernel/chio-kernel/src/kernel/validation.rs` and `kernel/evaluation.rs`
- SQLite budget authority: `crates/platform/chio-store-sqlite/src/budget_store/`
- Governed approval token: `crates/core/chio-core-types/src/capability/governance.rs`
- Governed validation: `crates/kernel/chio-kernel/src/kernel/governed_validation.rs`
- HushSpec threshold shape: `crates/guards/chio-policy/src/models.rs`
- Bilateral DSSE exact-two profile: `crates/trust/chio-federation/src/bilateral_dsse.rs`
- Capability negotiation: `crates/core/chio-core-types/src/capability/features.rs`
- Wire schemas: `spec/schemas/chio-wire/v1/`

## Cross-arc sequencing

- Enterprise broker prerequisite: `docs/superpowers/plans/2026-07-09-enterprise-hardening.md` may build broker-mediated execution and constraint validation in parallel, but production `max_executions` enforcement is blocked on Phase 2 here. Runtime composition installs a `SupplementalQuotaVerifier` implemented by the enterprise broker adapter; the kernel never depends on or trusts a caller-built broker type. The verified distinct quota joins the composite hold, and broker dispatch captures that hold once through the combined budget-and-revocation authority.
- Active-defense prerequisite: `docs/superpowers/plans/2026-07-09-security-active-defense.md` may build response planning and reversible state transitions in parallel, but heavy-action dispatch is blocked on Phase 3 here. It must consume `ThresholdApprovalRequirement`, `GovernedApprovalToken`, an operator-capability-bound threshold proposal, a generic approval-only `AdmissionOperation`, the shared replay reservation, and a typed `GovernedTransactionIntentBody::ActiveResponsePlan` rather than define another co-signature or substitute a raw plan hash for the governed intent hash.
- This plan has no dependency on enterprise broker or active-defense implementation crates. Shared types remain in core or kernel layers so the workspace dependency graph stays acyclic.

## Target type contracts

Names may change during implementation only if the replacement preserves these semantics.

```rust
// chio-core-types capability model
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
    pub schema: String,
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

// kernel budget authority
pub struct BudgetQuotaKey {
    pub profile: BudgetQuotaProfile,
    pub owner_id: String,
    pub grant_index: Option<u32>,
}

pub struct BudgetInvocationQuota {
    pub key: BudgetQuotaKey,
    pub max_invocations: u32,
}

// shared governed policy contract, independent of chio-policy
pub struct ThresholdApprovalRequirement {
    pub required: u32,
    pub eligible: BTreeMap<String, PublicKey>,
    pub proposal_timeout_seconds: u64,
    pub eligible_set_digest: String,
    pub policy_hash: String,
}

pub struct VerifiedApprovalSetBody {
    pub schema: String,
    pub canonical_token_digests: Vec<String>,
    pub policy_hash: String,
    pub required: u32,
    pub eligible_set_digest: String,
    pub request_id: String,
    pub governed_intent_hash: String,
    pub subject: PublicKey,
    pub authorization_capability_hash: String,
    pub proposal_id: String,
    pub threshold_proposal_hash: String,
    pub proposal_created_at: u64,
    pub proposal_deadline: u64,
}

pub struct AdmissionOperationV1 {
    pub kind: AdmissionOperationKind,
    pub operation_id: String,
    pub coordinator_authority_id: String,
    pub request_namespace_digest: String,
    pub request_id: String,
    pub capability_id: String,
    pub authorization_capability_hash: String,
    pub request_binding_hash: String,
    pub policy_hash: String,
    pub effect_class: SideEffectClass,
    pub threshold_proposal_hash: Option<String>,
    pub supplemental_authorization_digest: Option<String>,
    pub broker_attempt_id: Option<String>,
    pub budget_hold_id: Option<String>,
    pub approval_set_hash: Option<String>,
    pub execution_nonce_id: Option<String>,
    pub outcome_eligibility_digest: Option<String>,
    pub tool_outcome_id: Option<String>,
    pub terminal_result_id: Option<String>,
    pub terminal_result_digest: Option<String>,
    pub state: AdmissionOperationState,
    pub dispatch_state: AdmissionDispatchState,
    pub coordinator_lease_epoch: u64,
    pub version: u64,
    pub last_error: Option<String>,
    pub terminal_receipt_id: Option<String>,
    pub terminal_incident_id: Option<String>,
}
```

The aggregate quota owner is derived only after capability, delegation, and root-binding verification:

```text
capability       -> token.id
delegation_family -> SHA256("chio.aggregate-budget-family-key.v1\0" || canonical verified CA-signed binding body)
```

`delegation_chain.first().capability_id` is never accepted as family-root authority.

## Phase 0: lock the corrected baseline

### Task 1: Add characterization tests before changing wire types

**Files:**

- Modify tests under `crates/kernel/chio-kernel/src/kernel/tests/budget.rs`
- Modify tests under `crates/platform/chio-store-sqlite/src/budget_store/tests.rs`
- Modify tests under `crates/kernel/chio-kernel/src/kernel/tests/approval_flow.rs`
- Modify tests under `crates/kernel/chio-kernel/src/kernel/tests/budget_governed_call_chain.rs`

**Work:**

- [ ] Prove `max_invocations = 1` admits one dispatch and denies the second.
- [ ] Prove two different grants use distinct existing grant counters.
- [ ] Prove a pre-dispatch guard denial reverses the existing invocation mutation.
- [ ] Prove an execution that may have reached the tool server is not made freely retryable.
- [ ] Prove SQLite restart preserves invocation counts and idempotent event handling.
- [ ] Prove the current governed token binds request ID, intent hash, subject, signer, decision, and time.
- [ ] Prove replay-store unavailability denies governed admission.

**Gate:**

```bash
cargo test -p chio-kernel budget
cargo test -p chio-kernel approval
cargo test -p chio-store-sqlite budget_store
```

Commit: `test(security): lock budget and governed approval baseline`

## Phase 1: signed aggregate-budget model

### Task 2: Add the issuance body and authenticated family-root binding

**Files:**

- Modify `crates/core/chio-core-types/src/capability/token.rs`
- Modify `crates/core/chio-core-types/src/capability/attenuation.rs`
- Modify `crates/core/chio-core-types/src/capability/validation.rs`
- Modify `crates/core/chio-core-types/src/capability/scope.rs`
- Modify `crates/core/chio-core-types/src/delegation_receipt.rs` if needed for the attenuation projection
- Keep capability-authority and HTTP issuance fail closed until atomic aggregate enforcement is installed
- Modify every `CapabilityTokenBody` constructor reported by the compiler

**Work:**

- [ ] Add `AggregateInvocationBudget`, `AggregateInvocationScope`, `AggregateBudgetRootBindingBody`, and `AggregateBudgetRootBinding` with strict serde shapes.
- [ ] Add `aggregate_invocation_budget: Option<...>` to both `CapabilityToken` and `CapabilityTokenBody`. `CapabilityTokenSigningBody` and `CapabilityTokenAttenuationBody` receive it through their flattened `CapabilityTokenBody`; do not add a second serialized field.
- [ ] Update `CapabilityToken::body()`, `sign`, `sign_with_backend`, `sign_attenuated`, token reconstruction, verification, and every issuance constructor. This is required because the public sign APIs accept `CapabilityTokenBody`.
- [ ] Use `skip_serializing_if = "Option::is_none"` in the body and prove an absent field preserves the exact prior canonical signing bytes. Disable legacy-body fallback whenever the field is present.
- [ ] Validate `max_invocations` without rejecting zero.
- [ ] Reject `AggregateInvocationScope::Capability` when the token scope authorizes `Operation::Delegate`; delegable aggregate limits must use family scope.
- [ ] Require `root_binding = None` for capability scope and `Some(verified binding)` for family scope.
- [ ] Implement `AggregateBudgetRootCommitment` and domain-separated root hash `SHA256("chio.aggregate-budget-root-commitment.v1\0" || canonical_json(commitment))`.
- [ ] Add a direct-CA issuance helper that creates the commitment, signs `"chio.aggregate-budget-root.v1\0" || canonical_json(binding_body)` with the CA key, inserts the binding into `CapabilityTokenBody`, and then signs the complete token.
- [ ] Keep production authority emission disabled until aggregate quota reservation and dispatch capture are authoritative.
- [ ] Accept a v1 family root only when the token has an empty delegation chain, the issuer is a trusted CA, the binding signer equals the token issuer, and every bound root field matches the pre-binding commitment.
- [ ] Require every descendant to preserve the byte-identical canonical root binding and identical family maximum. Reject descendant lowering, raising, omission, and family creation beneath an unbound parent.
- [ ] Resolve and verify the signed direct-root capability from verifier-owned lineage for every descendant before comparing aggregate state. Missing authenticated root evidence denies; a subject-signed delegation link is not proof that the root had no family budget.
- [ ] Bind descendants to the root: require the first verified delegation link's capability ID, delegator, and scope hash to match root ID, root subject, and root scope hash, and require descendant expiry no later than root expiry.
- [ ] Derive the family quota owner from the verified root-binding digest. Never trust `delegation_chain.first().capability_id` as the family owner.
- [ ] Extend the attenuation witness and delegation receipt with root-binding-digest and immutable-maximum preservation.
- [ ] Extend every signed delegation link with the same preservation projection. Treat it as mutation evidence only, never as a replacement for the verified direct-root token.

**Tests:**

- absent-field signing fixture unchanged
- zero limit round trip
- direct CA family root accepted
- family created by a delegated issuer rejected
- descendant with identical binding and maximum accepted
- lowered or raised descendant family maximum rejected
- family-to-capability rejected
- family-budget omission rejected
- capability-scoped budget with delegate authority rejected
- root and descendants derive the same family owner
- forged root capability ID rejected
- forged root commitment hash rejected
- wrong root issuer or signature rejected
- changed root subject, expiry, scope hash, or maximum rejected
- valid binding grafted onto an unrelated delegation chain rejected
- tampered delegation chain fails before quota derivation

**Gate:**

```bash
cargo test -p chio-core-types aggregate_invocation
cargo test -p chio-kernel-core delegation
cargo fmt --all -- --check
```

Commit: `feat(core-types): add aggregate invocation budget`

### Task 3: Negotiate the new capability semantic

**Files:**

- Modify `crates/core/chio-core-types/src/capability/features.rs`
- Modify `crates/core/chio-core-types/src/capability/token.rs`
- Modify `crates/core/chio-core-types/src/capability/attenuation.rs`
- Modify `crates/core/chio-core-types/src/capability/validation.rs`
- Modify `crates/core/chio-core-types/src/capability/scope.rs`
- Modify `crates/core/chio-core-types/src/delegation_receipt.rs` if needed for the attenuation projection
- Keep capability-authority and HTTP issuance for both negotiated budget forms disabled until atomic enforcement is installed
- Modify capability-verification entry points in `crates/kernel/chio-kernel-core/src/capability_verify.rs`
- Modify `crates/kernel/chio-kernel/src/capability_lineage.rs`
- Modify `crates/platform/chio-store-sqlite/src/capability_lineage.rs`
- Modify the SQLite lineage schema initializer and migration tests
- Modify portable entry points in `chio-kernel-browser`, `chio-kernel-mobile`, and `chio-cpp-kernel-ffi`
- Modify federation handshake tests in `crates/trust/chio-federation/`

**Work:**

- [ ] Add `aggregate_invocation_budget` as a string-keyed feature.
- [ ] Add `cumulative_approval_budget` as a string-keyed feature and a strict
  `RequireCumulativeApprovalAbove { threshold: MonetaryAmount,
  approval_budget_id, approval_budget_epoch,
  cumulative_approval_root_binding: Option<CumulativeApprovalRootBinding> }` wire
  variant with conditional root-binding requirements. Preserve the legacy
  `RequireApprovalAbove { threshold_units }` variant as explicitly per-request;
  it never silently claims cumulative enforcement.
- [ ] Add a domain-separated `CumulativeApprovalRootBinding` for delegable
  `RequireCumulativeApprovalAbove`. It binds the CA-authenticated family root, root subject
  and scope, approval budget id/epoch, currency, threshold and expiry. Every
  descendant preserves its canonical bytes; a delegated cumulative constraint
  without that binding rejects.
- [ ] Add `cumulative_approval_root_binding: Option<...>` to the strict capability
  body and signing/attenuation projections. It is absent for a nondelegable direct
  constraint and required for every delegable root or descendant. Attenuation may
  narrow threshold/expiry only as the signed binding permits and never replace
  family, budget id/epoch, currency, subject, or scope.
- [ ] Keep `v1_default()` disabled. Enable only in the rollout profile after storage is ready.
- [ ] Reject a token carrying the aggregate field when the negotiated intersection does not enable it.
- [ ] Persist the exact signed capability token as an optional field in every verifier-owned lineage snapshot. Store it as nullable JSON, preserve its signature-bearing semantics through replication and evidence export, and never reconstruct signature authority from scalar snapshot columns.
- [ ] Resolve the first signed direct-root token for every delegated capability when either aggregate or cumulative approval semantics are enabled. A legacy snapshot with no signed token denies on those negotiated paths while remaining readable when both features are disabled.
- [ ] Add the optional signed direct-root token to portable verification and evaluation envelopes. Feature-enabled delegated verification with no root token denies.
- [ ] Reject portable aggregate and cumulative family chains with more than one delegation link until every hop carries an authenticated child-scope witness that proves intermediate scope and issuance chronology.
- [ ] Apply the same check in browser, mobile, FFI, federation, and direct kernel entry points.
- [ ] Add mixed-version tests proving the field is denied rather than ignored.
- [ ] Prove cumulative-approval siblings derive the same bound family owner and
  reject omission, mutation, or delegated creation of the binding.
- [ ] Keep production authority emission disabled until the composite hold owns
  cumulative approval reservation and dispatch capture.

Commit: `feat(core-types): negotiate aggregate invocation budgets`

## Phase 2: atomic aggregate enforcement

### Task 4: Extend the budget hold and mutation model

**Files:**

- Modify `crates/kernel/chio-kernel/src/budget_store.rs`
- Modify `crates/kernel/chio-kernel/src/budget_store/in_memory.rs`
- Create `crates/kernel/chio-kernel/src/supplemental_quota.rs`
- Modify budget-store property and loom tests

**Work:**

- [ ] Add structured `BudgetQuotaKey` and `BudgetInvocationQuota` types.
- [ ] Define explicit profiles for grant invocation, aggregate capability invocation, aggregate family invocation, and supplemental broker-capability execution.
- [ ] Add the authority-derived cumulative-approval account key and
  `PendingApproval -> Authorized -> Captured | ReversedBeforeDispatch`
  operation-owned substate specified by `AE-CUMULATIVE-APPROVAL-1` in the WS9
  design. Bind issuer/family owner, budget id/epoch, delegation-family root, and
  currency.
- [ ] In the same composite-hold lock, checked-add reserved and captured
  authorized units. Store the immutable root authority threshold on the account
  and the verified effective leaf threshold on the operation reservation. At or
  above the effective threshold always reserve `PendingApproval`; a separate
  verified-approval CAS advances that same reservation to `Authorized` without
  repeating the hold. This prevents concurrent sub-threshold bypass without
  silently tightening sibling constraints.
- [ ] Define a kernel-owned `SupplementalQuotaVerifier` port over opaque signed extension bytes and a kernel-built verification context. Its installed trusted implementation returns a request-bound `VerifiedSupplementalQuotaClaim`; no request field directly supplies a quota key or maximum.
- [ ] Recheck capability digest, subject, authenticated request namespace,
  operation and request IDs, destination, complete normalized arguments digest,
  expiry, supplemental revocation ids, artifact digest, and negotiated profile on
  the verifier result before deriving the broker quota key. Bind the
  composition-supplied verifier identity/configuration digest and exclusive
  artifact expiry into the hold, then recheck expiry at trusted capture time.
  Missing verifier, unknown profile, or mismatched context denies.
- [ ] Build a canonical revocation set, sorted by UTF-8 bytes, from the leaf
  capability id, every verified delegation-chain ancestor capability id, and
  every supplemental revocation id. Bind its digest into the hold and
  `AdmissionOperation`; reject duplicates, omissions, additions, and
  post-verification mutation. Canonical storage reconstruction proves only
  sort, uniqueness and digest consistency; the kernel coordinator derives
  semantic completeness directly from validated lineage.
- [ ] Extend `BudgetAuthorizeHoldRequest` with a sorted list bounded by `MAX_INVOCATION_QUOTAS_PER_ADMISSION = 8`.
- [ ] Extend authorized, denied, reverse, capture, and mutation records with all affected quota keys and counts.
- [ ] Record one immutable maximum with each quota key only when the all-or-none
  authorization succeeds. A denial records its mutation event but creates no
  absent quota or cumulative-account row and defines no maximum. Re-presenting
  an existing key with a different maximum is an invariant failure, not an
  update.
- [ ] Extend `authorize_budget_hold`, `reverse_budget_hold`,
  `release_budget_hold`, `reconcile_budget_hold`, and `capture_budget_hold` so
  every implemented transition preserves all quota members, both substates,
  cumulative approval state and approval-set digest, authority lease metadata,
  guarantee level, and commit index. Rich terminal trait defaults fail closed. A
  backend implements one only when it can return the truthful event-time
  projection; it never synthesizes missing hold state or aliases one transition
  to another. The unstructured single-grant authorization default remains a
  compatibility adapter; production backends override it to return an atomic
  event-time projection.
- [ ] Add `capture_invocation_reservations` as the dispatch-commit transition
  for invocation quotas. Do not overload monetary `capture_budget_hold` with an
  ambiguous whole-hold terminal state. A hold authorized with positive monetary
  exposure must still be `Exposed` with positive remaining exposure when its
  invocation is captured; full pre-dispatch release makes capture fail closed.
- [ ] Add mutation kinds for invocation reservation, capture, and reversal if the current kinds cannot represent them truthfully.
- [ ] Keep `try_increment` as a compatibility wrapper through the same authoritative path.
- [ ] In one lock acquisition, check every limit and mutate all or none.
- [ ] Reject duplicate or ambiguous keys, more than eight invocation claims, unknown profiles, and arithmetic overflow.
- [ ] Derive the broker key from the installed verifier's request-bound claim as a domain-separated digest of verified broker capability ID, issuer, destination, and request-constraint digest. Its maximum comes only from that verified signed artifact.
- [ ] Require nonempty paired `hold_id` and `event_id` values for structured
  durable authorization, invocation capture, and captured-invocation
  cancellation. Legacy rich mutation calls may omit both or use a nonempty
  event-only identity for wire compatibility; a supplied hold always requires a
  nonempty event. Empty or partial structured identities fail closed.
- [ ] Replay only the exact stored `event_id` when every input matches. A new
  event against a superseded hold state, reuse with different inputs, or replay
  after a later terminal transition is an invariant error rather than an
  idempotent success.
- [ ] Make timeout reversal of a cumulative approval reservation compare and
  swap from expected `PendingApproval`. Approval attachment compare and swaps
  the same participant to `Authorized`; if they race, exactly one transition
  succeeds and the loser observes the changed state.
- [ ] Track legacy unheld reversible invocations per capability and grant, not
  by exact exposure amount. Partial exposure release does not consume that
  invocation's reversal right; only full reversal or settlement consumes it.
- [ ] Preserve `BudgetEventAuthority`, `BudgetGuaranteeLevel`, and commit metadata.

**Required state machine:**

```text
invocation: absent -> authorized -> captured
                                -> reversed
            absent -> denied

monetary: none -> exposed -> released
                         -> reconciled
                         -> captured
                         -> reversed
```

Invocation `captured` and `reversed` are terminal only for the invocation substate. Monetary capture and reconciliation remain independent after invocation capture, but release and reverse cannot cross that dispatch commitment fence. Only the explicit legacy synthesized single-grant pre-dispatch cancellation may reverse captured invocation and exposure together; explicit composite and cumulative captures are terminal. The entire hold is terminal only when every present substate is terminal. Repeating the exact same transition event is idempotent. A different event or an incompatible terminal transition fails closed.

Strict execution-nonce preflight uses a distinct deterministic internal hold
namespace from an executable admission and derives its authorization event as
`{hold_id}:authorize`. Cleanup derives a deterministic rollback event from that
authorization event and commit index. Its compensated hold and event remain
append-only tombstones, so a lost acknowledgement can replay the exact cleanup
but a repeated nonce-free preflight cannot mint another nonce. The nonce-bearing
execution uses its separate executable hold and cannot reopen the preflight hold.
A confirmed payment decline likewise leaves that executable request identity
terminal; a later attempt uses a fresh request identity and nonce rather than
deleting or recycling the compensated authorization.

**Tests:**

- grant plus aggregate plus broker quota pass in one hold
- either quota exhausted changes neither quota
- exhaustion of any one among three quotas changes none
- two threads contending for the last unit admit exactly one
- concurrent 60+60 requests against a cumulative threshold of 100 cannot both
  dispatch without the required approval
- sibling delegated grants share the authenticated family-root accumulator
- duplicate key rejected
- denied authorization against absent quotas creates no quota or cumulative row
- a later authorization may define a previously denied key's signed maximum
- existing key with changed maximum rejected
- nine quota claims rejected
- empty and partial structured identities rejected; legacy event-only mutation accepted
- same event retry stable
- mismatched event retry rejected
- different event after a later transition rejected
- invocation capture preserves live monetary exposure
- fully released positive exposure cannot capture invocation
- monetary reconciliation preserves captured invocation counts
- pre-dispatch reverse restores all invocation reservations and exposure
- approval attachment racing pending-approval timeout has exactly one winner
- strict nonce preflight retries one deterministic cleanup and cannot reopen its hold
- legacy partial release does not consume the per-grant reversal right
- unsupported rich transition defaults fail closed

Commit: `feat(kernel): authorize composite invocation quotas atomically`

### Task 5: Implement durable SQLite and remote authority semantics

**Files:**

- Create `crates/core/chio-core-types/src/store_fence.rs` and export the
  backend-neutral `StoreMutationFence`
- Modify `crates/platform/chio-store-sqlite/src/budget_store/`
- Modify `crates/platform/chio-store-sqlite/src/revocation_store.rs`
- Create `crates/platform/chio-store-sqlite/src/serving_owner.rs`
- Modify `crates/platform/chio-control-plane/src/trust_control/budget_handlers.rs`
- Modify `crates/platform/chio-control-plane/src/trust_control/authority_handlers.rs`
- Modify `crates/platform/chio-control-plane/src/trust_control/service_types.rs`
- Modify `crates/platform/chio-control-plane/src/trust_control/service_runtime/budget.rs`
- Add a forward-only SQLite migration through the existing schema initializer

**Work:**

- [ ] Store structured quota columns, not a delimiter-concatenated key.
- [ ] Make the structured quota key itself primary or unique. Store `max_invocations` as an immutable checked column on that one row; never use `(quota_key, max_invocations)` as the uniqueness constraint because that permits multiple maxima for one key.
- [ ] Use one `BEGIN IMMEDIATE` transaction to load, compare, reserve, and append all rows.
- [ ] Provision a joint SQLite authority before serving it. Bind one canonical
  database inode to one protected lock inode and store UUID, advance an exclusive
  owner epoch and lease on every serving open, and verify that exact durable fence
  inside every authority write transaction. Independent budget or revocation
  opens reject a provisioned database. Offline forward migrations acquire the
  same lock and reject a live serving owner.
- [ ] Give every structured hold and event an immutable projection discriminator,
  bound revocation-set digest, expected child counts, and optional-child presence
  flags. Startup and every loader reject missing, extra, noncanonical, or
  contradictory quota, artifact, revocation, cumulative-approval, and lifecycle
  projections. Never infer structured enforcement from one nullable child row.
- [ ] Persist authorization outcome plus invocation and monetary before/after
  states for every mutation event, including legacy events. Migrate old rows from
  their ordered hold history, preserve the fields through delta and snapshot
  DTOs, and reject ambiguous old-peer projections rather than inventing a state.
- [ ] Seal the joint authority against legacy business, replication, import,
  delete, and direct-usage write paths. Only composite authorization and lifecycle
  mutations over an existing structured hold may mutate its budget state. Legacy
  rows remain readable and migratable but cannot become a second authority path.
- [ ] Once a capability/grant has any durable structured authorization history,
  including a denial or terminal reversal, reject unstructured increment, charge,
  import, and direct-usage mutations for that identity. A terminal hold does not
  erase the policy boundary.
- [ ] Persist invocation and monetary substates plus every quota member so crash recovery can finish, compensate, or reconcile deterministically.
- [ ] Persist cumulative-approval authority accounts and operation reservations
  in the same transaction. Enforce immutable budget id/epoch, root authority
  threshold, root grant, and currency; persist the verified effective threshold
  per operation and expose lookup by `operation_id`.
- [ ] Return counts, authority lease, guarantee level, and commit index from the same transaction.
- [ ] Extend remote request and response DTOs without dropping authority metadata.
- [ ] Let the kernel include only the installed supplemental verifier's result in the same composite request. Do not accept a caller-built broker claim, add a broker-only counter endpoint, or make the broker reserve that key a second time.
- [ ] Expose invocation capture separately from monetary capture, release, and reconciliation through local and remote DTOs.
- [ ] Persist complete prior revocation-observation provenance without presenting
  it as combined-capture proof. A commit index copied from an independent read is
  not evidence that revocation, operation state, and budget capture were one
  commit.
- [ ] For a fresh joint authorization, require any presented observation to use
  the active fence and read every admission-bound revocation member in the same
  transaction. Revoked-first records a durable denial. Exact event replay may
  return its historical observation under a later active epoch. This early check
  does not replace Task 6's capture-time revocation check.
- [ ] Keep the existing remote cluster profile `AdvisoryPosthoc`. Do not label
  quorum acknowledgements or replicated SQLite rows `HaLinearizable`, and reject
  them for non-escrowed hard family limits. A real HA authority requires one
  consensus log for operation, revocation, and budget commands and lands only
  with its conformance environment.
- [ ] Do not expose a partial `AdmissionCaptureAuthority` or wire endpoint in this
  task. Its first implementation lands with the durable `AdmissionOperation` in
  Task 6, where the operation precondition and combined outcome can be stored and
  replayed from the same authority commit.
- [ ] Keep composite joint-authority activation out of the normal control-plane
  constructor in this task. Injected tests prove the owner and wire contracts;
  Task 6 owns privileged provisioning, production runtime composition, and
  startup rejection of incompatible multi-worker or local-store deployments.
- [ ] Route every rich hold lifecycle method through a versioned endpoint and
  require its exact event-time lifecycle, usage, authority, quota, admission,
  and cumulative projections when present. Versioned projections may omit the
  admission binding only for a genuinely legacy hold with no structured quota
  or cumulative children. Keep only the low-level compatibility methods on v1.
  An older server must reject an unknown semantic operation before mutation
  rather than ignore a new field or return an optional projection after applying
  a different legacy transition.
- [ ] Validate imported usage only as the final projection of a legal ordered
  event chain for the same capability and grant. Reject free-standing higher-seq
  snapshots that lower or otherwise forge invocation, exposure, or realized
  spend counters, and reject holdless events whose usage sequence and after-state
  do not match that chain.
- [ ] Preserve old rows and existing grant-budget reports through migration.

**Crash and restart tests:**

- crash before transaction commit leaves no hold
- crash after commit restores an authorized hold
- retry after response loss returns the same decision
- retry after owner-epoch rotation returns the original decision and commit
  metadata while new mutations use the active fence
- restart after invocation capture preserves exhaustion and unresolved monetary exposure
- restart after monetary reconciliation preserves captured invocation counts
- restart after reversal preserves capacity
- restart in `PendingApproval` returns the same operation reservation; approval
  attachment versus timeout has one CAS winner
- an existing key cannot be reopened with a different maximum after restart
- direct SQL or API insertion of a second maximum for the same quota key fails the unique-key invariant
- imported mutation cannot regress sequence, authority epoch, or count
- a compensated authorization remains an append-only terminal tombstone on the
  leader and a fresh follower; retry requires a fresh hold and event identity
- in-bounds quota, cumulative-account, lifecycle, or trusted-capture-time SQL
  drift is rejected at serving open before it can change admission capacity
- two clients sharing one local serving owner and racing for the last unit admit
  exactly one
- concurrent provisioning creates one durable store identity and one serving
  lock; a second serving open and every stale handle fail closed
- projection-child deletion, discriminator loss, forged historical revocation
  provenance, and legacy writer attempts fail before a structured mutation
- legacy lifecycle events round-trip exactly through SQLite, delta, and snapshot
  paths; ambiguous old-peer lifecycle fields fail closed

**Gate:**

```bash
cargo test -p chio-store-sqlite budget_store
cargo test -p chio-control-plane budget
```

Commit: `feat(store-sqlite): persist composite invocation holds`

### Task 6: Reorder kernel admission and project signed receipts

**Files:**

- Create `crates/kernel/chio-kernel/src/admission_operation.rs`
- Create `crates/kernel/chio-kernel/src/tool_outcome.rs`
- Create `crates/kernel/chio-kernel/src/dispatch_status.rs` for the closed status
  provider API and private verified attempt-lifecycle results
- Create `crates/core/chio-core-types/src/provider_attempt.rs` for canonical
  provider checkpoint and invocation-blob bindings
- Use the backend-neutral `StoreMutationFence` established in Task 5
- Create `crates/platform/chio-store-sqlite/src/admission_operation_store.rs`
- Create `crates/platform/chio-store-sqlite/src/admission_capture_authority.rs`
- Create `crates/platform/chio-store-sqlite/src/tool_outcome_store.rs`
- Modify `crates/platform/chio-store-sqlite/src/serving_owner.rs`
- Create `crates/platform/chio-store-sqlite/src/obligation_store.rs`
- Create or extend the kernel `AdmissionCaptureAuthority` port used by combined broker capture
- Modify admission-operation service DTOs and handlers under `crates/platform/chio-control-plane/src/trust_control/`
- Modify `crates/kernel/chio-kernel/src/kernel/validation.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/evaluation/mod.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/governed_validation.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/responses/finalization.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs`
- Modify `crates/kernel/chio-kernel/src/runtime.rs`
- Modify `crates/kernel/chio-kernel/src/transport.rs`
- Modify `crates/kernel/chio-kernel/src/receipt_store.rs`
- Modify `crates/kernel/chio-kernel/src/execution_nonce.rs`
- Modify `crates/kernel/chio-kernel/src/revocation_runtime.rs`
- Modify `crates/platform/chio-store-sqlite/src/approval_store.rs`
- Modify `crates/platform/chio-store-sqlite/src/execution_nonce_store.rs`
- Modify `crates/platform/chio-store-sqlite/src/receipt_store.rs`
- Modify `crates/platform/chio-store-sqlite/src/receipt_store/bootstrap/open.rs`
- Modify `crates/platform/chio-store-sqlite/src/receipt_store/tests/single_writer.rs`
- Modify `crates/platform/chio-store-sqlite/src/budget_store.rs`
- Modify `crates/platform/chio-store-sqlite/src/budget_store/store.rs`
- Modify `crates/platform/chio-store-sqlite/src/budget_store/trait_impl.rs`
- Modify `crates/platform/chio-store-sqlite/src/lib.rs`
- Modify `crates/products/chio-cli/src/cli/types.rs` and runtime wiring for the
  privileged `chio store provision` command or configured lock-broker client
- Modify receipt tests in `crates/kernel/chio-kernel/src/kernel/tests/`

**Work:**

- [ ] Split pure validation from authoritative state reservation.
- [ ] Complete schema, signature, trust, time, revocation, delegation, request binding, governed-token signature, runtime evidence, guard, and runtime-admission checks before the aggregate hold.
- [ ] Resolve the matching grant before building quota keys. For supplemental authorization, invoke only the installed trusted `SupplementalQuotaVerifier`, recheck its request context, and derive the key from its verified result. Do not import `chio-secret-broker` into kernel or accept a caller-built claim.
- [ ] Define `AdmissionOperationKind::{ToolDispatch, GovernedActiveResponse,
  GovernedEconomicMutation}`. The last kind covers authority-mediated state
  mutation such as WS2 assignment without inventing another coordinator. Derive
  `operation_id = SHA256("chio.admission-operation.v1\0" || canonical_json({ kind, coordinator_authority_id, request_namespace_digest, request_id, capability_id, authorization_capability_hash, request_binding_hash }))`. The authenticated namespace is part of both the global primary-key identity and replay unique key. The request hash covers only immutable request and effect fields: arguments or response plan, governed intent, policy requirements, destination, pricing selection, and settlement mode. It excludes the authority-generated threshold proposal, approval-set membership, supplemental authorization artifacts, and nonce references so an `ApprovalRequired` result can resume under the same operation. Persist `AdmissionOperationV1::Prepared` before any authority mutation.
- [ ] Compare-and-swap each authority-generated proposal hash, verified approval-set hash, supplemental authorization digest, and execution nonce reference from null exactly once before `ReadyToDispatch`. Normalize approval membership as sorted canonical token digests. A matching retry is idempotent; a different value after attachment denies.
- [ ] Require a durable `AdmissionOperationStore` whenever aggregate, broker,
  threshold, monetary, or side-effecting admission is active. Bind a unique
  authenticated `(request_namespace_digest, request_id)` replay key. Missing or
  unavailable storage denies before any reservation.
- [ ] Look up that replay key and persist a fresh `Prepared` operation before any
  authority mutation. The later composite budget call reserves any cumulative
  participant under the operation ID together with every quota and monetary
  claim. Derive proposal time, effective threshold, and budget epoch from that
  durable result; then CAS-attach the exact proposal bytes/digest and persist
  `ApprovalRequired` before returning. A crash between reservation and attachment
  queries the same hold and derives the same proposal; a matching retry returns
  the stored proposal.
- [ ] Advance saga state with compare-and-swap on `version` under a fenced coordinator lease so an executor and recovery worker cannot both commit dispatch.
- [ ] Implement RFC-0006's pending shared serving-owner amendment. Privileged
  provisioning initializes the durable store UUID and creates/fsyncs the
  protected UUID lock inode; serving only opens and verifies an existing inode.
  Return one clonable `SqliteServingOwner` and
  `StoreMutationFence { store_uuid, lease_id, owner_epoch }`. Receipt,
  budget/payment, obligation, outcome, operation and later FROST stores all reuse
  it and check the fence inside every mutation/recovery transaction. Reject
  missing/partial provisioning, wrong owner/mode/link count, symlink/hardlink/
  rename/copy aliases, lock replacement, independent mutable reopen and stale
  recovery owners before actors start.
- [ ] Use SQLite only for single-node saga authority. Multi-worker deployment requires a shared linearizable operation store and fenced lease; configuration that combines multiple dispatch workers with a local-only store fails startup.
- [ ] For supplemental broker authorization, call authenticated local `RegisterAttempt` after `Prepared` but before the remote budget call. It receives deterministic operation, attempt, hold, event, proof, and request digests, validates non-secret constraints, persists and fsyncs the broker intent, and returns an idempotent acknowledgement. Persist `BrokerAttemptRegistered`; failure consumes no budget.
- [ ] Authorize the cumulative participant plus the bounded grant, aggregate,
  broker, and monetary claims in one hold under `operation_id`. A
  `PendingApproval` result retains that same hold and cannot capture. After a
  separate verified-approval CAS advances it to `Authorized`, persist
  `BudgetAuthorized` without repeating authorization.
- [ ] Extend approval replay and nonce authorities with operation-owned `reserved`, `committed`, and `cancelled` states plus lookup by `operation_id`. A cancelled record remains a replay tombstone.
- [ ] Reserve approval state, persist `ApprovalReserved`, reserve the execution nonce, then persist `ReadyToDispatch`. Only then may the registered broker attempt materialize and prepare credentials; it still cannot send upstream.
- [ ] When cumulative approval is required, return only the stored proposal after
  retaining the same immutable operation and composite `PendingApproval` hold.
  On retry, verify and compare-and-swap attach the approval set exactly once,
  advance that existing cumulative substate to `Authorized`, and never mutate or
  repeat the authorize request or derive a new operation from approval
  membership.
- [ ] Persist `CapturePending`, commit approval and nonce reservations, then perform the applicable capture. Ordinary dispatch calls `capture_invocation_reservations`; broker dispatch calls `AdmissionCaptureAuthority` with the hold, operation, canonical leaf-plus-ancestor-plus-supplemental revocation set and digest, and verified authorization-artifact digest. A capture denial compensates before dispatch while retaining replay tombstones.
- [ ] Define `AdmissionCaptureAuthority` only over an authority that also owns the
  relevant revocation writes and can read the durable operation row. The local
  implementation is available only when operation, budget, and revocation tables
  share one serving owner and one `BEGIN IMMEDIATE` transaction. Reject separate
  writers at composition time.
- [ ] Persist one combined-capture commit record. It binds the exact operation
  version and `CapturePending` precondition, capability and grant, hold and event,
  complete leaf-plus-ancestor-plus-supplemental revocation set, authorization
  artifacts, every quota member, authority-sourced trusted time, outcome, and any
  closed denial reason. Captured results prove the time is within authorization
  expiry. Denials persist `allowed = false` and replay the same reason. A copied
  pair of budget and revocation indices is not a combined commit.
- [ ] Route revocations for combined-capture capabilities through the same
  authority. Test both orders of the race: revoked-first denies durably, while
  captured-first consumes every quota exactly once. Bound and validate every
  revocation identifier before storage lookup or mutation.
- [ ] After successful capture, persist `DispatchCommitted` and only then authorize the broker's upstream send or begin the ordinary tool-server side effect. Recovery may complete the state write after discovering a capture under `operation_id`, because code cannot send while the operation remains `CapturePending`. After `DispatchCommitted`, never resend without downstream idempotency. The enterprise broker performs no second reservation.
- [ ] Make both exact invoke sites call one shared coordinator and immediately
  persist the content-addressed output plus `ToolOutcomeRecordV1` before
  post-return guards or settlement. Add `PostReturnEvaluationRecordV1`: persist
  exact pipeline/policy versions, trusted time and inputs before evaluation,
  persist every external/stateful result, and finalize output, cost, verdict and
  disposition by CAS. Pure replay uses only frozen inputs; external replay requires
  authenticated idempotent lookup. Ambiguity freezes rather than reevaluating
  current state. Expose side-effect-free lookup by operation.
- [ ] Add optional `DispatchStatusProvider` over exact operation and attempt.
  Without it, ambiguous committed handoff is incident-only and freezes holds;
  with it, accept only verified `NotAccepted`, `Pending`, `Accepted {
  acceptance_ref }`, `Completed { tool_outcome_ref }`, or `Unknown`. Bind
  transport identity/key epoch and the current external monotonic attempt
  checkpoint. `Accepted` requires authenticated retrieval of its exact envelope
  and proves only that cancellation is impossible. `Completed` requires
  authenticated `fetch_completed_outcome` returning the exact bound bytes, cost
  and terminal evidence, which must be persisted locally before evaluation. A
  bare or unavailable ref remains outcome-unknown.
- [ ] Make `VerifiedTransportNotAccepted` constructible only from a qualified
  external provider-attempt lifecycle. Local queue work begins
  `LocalQueuedStaged` and is non-executable. External `Pending -> Accepted |
  Cancelled` is one linearizable race; `Cancelled` permanently disables the
  staged row, while `Accepted` binds rollback-independent invocation-blob
  availability and can never cancel. A worker may invoke only after reading the
  current external checkpoint and winning `Accepted -> Executing` with an
  execution lease/fence. It stores an authenticated terminal outcome before
  `Executing -> Completed`. Recovery reads the anchor first and reconstructs
  accepted work from the bound blob. After a possible effect it uses
  authenticated tool-side status or separately qualified same-key idempotent
  invocation; otherwise it remains unknown without rerun. Task 6 owns these core
  types, verifier boundaries, and fail-closed default. WS3 Phase 3 owns a concrete
  provider/anchor adapter and cannot activate until its qualification matrix
  passes; no current generic tool server is treated as qualified.
- [ ] Reverse only when dispatch provably did not begin.
- [ ] Reconcile, capture, or release monetary exposure independently of invocation
  capture. For release, atomically persist a bounded immutable canonical
  `MonetaryReleaseEvidenceV1` bundle plus its kind/id/digest/version with the
  settle action before the rail call; a pointer to mutable proof state is
  insufficient. Recovery reconstructs the private verified authority from that
  exact bundle. `HoldPlaced + NoAuthorization` likewise needs a persisted
  `VerifiedPreDispatchNoEffect` bundle before local exposure release. After
  `DispatchCommitted`, an absent settle action or evidence bundle never
  authorizes release.
- [ ] Make compensation idempotent: before dispatch, reverse the budget hold and cancel approval and nonce reservations without deleting their tombstones. After dispatch commitment, never reverse invocation quotas.
- [ ] On recovery, query each authority by `operation_id` when its commit may have preceded the saga-state write. Never repeat a side effect merely because the coordinator row is stale.
- [ ] Permit resend after `DispatchCommitted` only when the downstream protocol verifies `operation_id` as an idempotency key. Otherwise finish as `OutcomeUnknownAfterDispatch`.
- [ ] Apply identical ordering to top-level and nested session flows.
- [ ] Add RFC-0003's typed `commit_admission_projection` transaction for the
  closed `AdmissionTerminalProjection`: completed receipt plus optional local
  sidecars, pre-dispatch compensation with verified no-effect evidence,
  post-commit verified non-acceptance, or outcome-unknown incident. Enforce legal
  source states and atomically bind the receipt or incident plus terminal
  operation. Add `EconomicMutationApplied` and `EconomicMutationNotApplied`
  variants that bind a typed signed terminal result plus audit event without a
  `ChioReceipt`. Retain every terminal operation as a request replay tombstone. Do
  not claim cross-database atomicity for the payment participant.
- [ ] Define closed `VerifiedNoEffectProof` with distinct private-constructor
  `VerifiedPreDispatchNoEffect` and cancellation-fenced
  `VerifiedTransportNotAccepted` payloads. Make the two terminal projections
  accept only their matching payload. Define `VerifiedContractualZeroCharge` and
  closed `MonetaryReleaseAuthority`; reject caller-built proof bytes and missing
  receipts as release authority.
- [ ] Add aggregate details to `budget_authority` receipt metadata: keys, immutable maxima, invocation and monetary substates, verified root-binding digest, broker key, event IDs, authority, guarantee, and commit index.
- [ ] Add operation ID, saga state, dispatch state, and compensation status to signed receipt metadata.
- [ ] Do not emit a separate `Burn` receipt subtype.
- [ ] Add a kernel-owned reservation entry point for broker-mediated execution that uses the same composite hold and capture contract without giving the broker direct database access.
- [ ] Add a generic approval-only coordinator entry point for `GovernedActiveResponse`. It verifies the operator capability, persists prepared and approval-reserved states, commits the approval set, writes `DispatchCommitted` before the first idempotent response effect, omits budget, capture, and nonce participants, and exposes a trusted control-plane port without creating an active-defense dependency.
- [ ] Add a generic `GovernedEconomicMutation` entry point. The authoritative
  mutation service is an idempotent saga participant keyed by `operation_id` and
  returns a versioned signed applied or permanently-not-applied result binding
  resource version/fence. Add private verified result types plus canonical
  `terminal_result_id`/digest bindings. Recovery queries that participant and
  terminalizes the local operation through the matching mutation projection;
  never claim a cross-store transaction or repeat the mutation from stale local
  state.

**Security tests:**

- table-driven fault injection immediately before and after every budget, approval, nonce, invocation-capture, monetary, and receipt mutation, and immediately before and after every saga-state write from `Prepared` through a terminal state
- malformed capability consumes nothing
- bad approval signature consumes nothing
- guard denial consumes nothing
- runtime-admission denial consumes nothing
- replay reservation failure reverses every quota
- crash after `Prepared` resumes or compensates without mutation
- crash after broker attempt registration but before budget authorization finds the pending attempt and consumes no budget
- broker registration acknowledgement loss reloads the same deterministic attempt rather than creating another row
- crash after budget commit but before `BudgetAuthorized` state write discovers and reverses or resumes the existing hold
- crash after approval reservation leaves a tombstone and reverses budget if dispatch was not committed
- crash after nonce reservation leaves both tombstones and reverses budget if dispatch was not committed
- crash after `ReadyToDispatch` follows the configured resume-or-compensate policy exactly once
- capture denial from revocation or exhaustion compensates the authorized hold without reaching `DispatchCommitted`
- crash after capture but before the `DispatchCommitted` state write discovers the capture and cannot have sent
- crash after `DispatchCommitted` never reopens invocation quotas or resends without downstream idempotency
- crash after invocation capture but before broker send does not resend without downstream idempotency
- crash after broker send but before response records `OutcomeUnknownAfterDispatch`
- crash after tool return but before settle-action persistence never releases a
  reversible hold and never redispatches the operation
- completed operation replay returns the retained receipt or conflicts without
  invoking the tool, including after terminal compaction
- receipt-side projection fault injection leaves no partial receipt, terminal
  operation, observer row, authorization consumption, eligibility transition, or
  obligation
- tool-outcome blob/row and resolved-outcome crash points either recover exact
  bytes/cost/disposition or freeze unknown; none infer release
- provider-completed refs require authenticated fetch of exact bytes/cost/evidence
  and local persistence; bare, unavailable, or mismatched refs freeze unknown
- provider staging is non-executable before external acceptance; race
  `Pending -> Accepted` against `Pending -> Cancelled`, then race executor claim
  against cancellation and prove exactly one legal external CAS wins
- kill and restore before/after local stage, external acceptance, executor claim,
  tool effect, terminal-result persistence and completion CAS; a cancelled slot
  never executes, accepted/executing/completed never cancels, and post-effect
  recovery without authenticated status or qualified same-key idempotency never
  reruns
- post-return evaluation crashes use frozen pure inputs or idempotent authenticated
  result lookup; a time-varying/stateful ambiguity never reruns or changes the
  settlement disposition
- each tool terminal projection commits operation plus receipt or incident
  atomically; each mutation projection commits operation plus typed terminal
  result/audit event locally; all reject illegal source states
- remote mutation acknowledgement loss queries by operation and binds one result;
  it never repeats the resource CAS or claims cross-store atomicity
- revocation and broker capture races serialize through one combined commit; no sequential-check implementation passes
- cumulative approval behavior and recovery are identical in top-level and
  nested evaluation paths
- a parity test fails if either `async_evaluation_core.rs` or
  `nested_flow_evaluation.rs` reaches `invoke`/`invoke_stream` without the shared
  `DispatchCommitted` helper and immediate durable outcome recorder
- UUID ownership tests cover privileged/partial provisioning, wrong lock
  owner/mode/link count, symlink, hardlink, renamed and copied-same-UUID databases,
  lock replacement, stale external recovery owners, and stale/cross-database
  receipt, budget/payment, obligation, outcome and FROST mutations
- revoking any delegation ancestor between validation and capture denies; omitting that ancestor from the capture set is an invariant failure
- missing or malicious supplemental verifier, caller-built quota key, wrong context binding, and kernel-to-broker dependency fail their respective tests or architecture gate
- approval-only active-response crash after reservation or dispatch commitment recovers one operation and applies at most once
- executor and recovery worker racing on the same operation lease commit dispatch at most once
- dispatch uncertainty consumes the invocation
- monetary cleanup can finish after invocation capture
- signed receipt metadata matches stored mutation rows
- nested and top-level behavior are identical

Commit: `feat(kernel): enforce aggregate invocation admission`

## Phase 3: threshold governed approval

### Task 7: Compile HushSpec approver requirements without a dependency cycle

**Files:**

- Add shared requirement types under `crates/core/chio-core-types/src/capability/governance.rs` or a focused sibling module
- Modify `crates/guards/chio-policy/src/compiler.rs`
- Modify `crates/guards/chio-policy/src/models.rs` validation
- Modify policy materialization in `crates/platform/chio-control-plane/src/policy.rs`
- Add a kernel-owned resolver trait and install it from the composition layer

**Work:**

- [ ] Define `ThresholdApprovalRequirement` independently of HushSpec.
- [ ] Define a deterministic kernel resolver interface keyed by the matched request and policy hash.
- [ ] Compile `ChioApproverSet.n/of/timeout_seconds` into the shared type.
- [ ] Define `timeout_seconds = None` as exactly 900 seconds and reject values above 3600 seconds.
- [ ] Resolve `of` identifiers through an authenticated, versioned approver directory. Hex public keys may be the initial identifier format; unresolved aliases fail policy load.
- [ ] Reject zero thresholds, thresholds above set size, duplicates, empty IDs, unsupported keys, and excessive timeout.
- [ ] Compute `eligible_set_digest = SHA256("chio.approver-set.v1\0" || canonical_json(sorted IDs and keys))` and bind it to the policy hash and threshold.
- [ ] Bind the compiled requirement to the loaded policy hash.
- [ ] Keep `chio-kernel` free of a `chio-policy` dependency.

**Tests:** malformed sets reject at load time, key-order changes do not change the compiled hash, stale policy hashes deny, and policy reload atomically replaces the resolver snapshot.

Commit: `feat(policy): compile threshold approver requirements`

### Task 8: Verify bounded sets of existing approval tokens

**Files:**

- Modify `crates/kernel/chio-kernel/src/runtime.rs`
- Modify `crates/core/chio-core-types/src/capability/governance.rs`
- Modify `crates/kernel/chio-kernel/src/kernel/governed_validation.rs`
- Modify active-response conversion in the composition layer without adding a core-to-active-defense dependency
- Modify approval tests and request builders reported by the compiler

**Work:**

- [ ] Add `approval_tokens: Vec<GovernedApprovalToken>` with an input ceiling of 32.
- [ ] During migration, normalize the singular `approval_token` to one element. Reject requests that supply both fields.
- [ ] Add policy-authority-signed `ThresholdApprovalProposalBody` carrying proposal ID, request, governed intent hash, subject, canonical authorizing-capability digest, policy hash, threshold, eligible-set digest, `proposal_created_at`, and exclusive `proposal_deadline`.
- [ ] Define `proposal_deadline = min(proposal_created_at + compiled timeout, authorizing capability expiry, governed operation expiry)` using checked arithmetic. Direct-set verification must verify the proposal signature, capability digest and validity, and `proposal_created_at <= now < proposal_deadline`.
- [ ] Add optional `threshold_proposal_hash` to `GovernedApprovalTokenBody` and `GovernedApprovalToken`. Require it for threshold tokens and include it in every signing path. Legacy one-of-one approval may omit it during migration.
- [ ] Factor current token verification into a pure function that does not mutate replay state.
- [ ] Verify every token's proposal hash, canonical intent hash, request ID, subject, authorizing-capability binding, decision, trusted signer, and signature.
- [ ] Require token issuance within `[proposal_created_at, proposal_deadline)` and token expiry no later than the proposal deadline.
- [ ] Require distinct token IDs, canonical token digests, and approver-key fingerprints.
- [ ] Count only signers in the policy-owned eligible map.
- [ ] Reject invalid extras rather than silently filtering them.
- [ ] Hash each complete canonical token, including its signature, as `SHA256("chio.governed-approval-token.v1\0" || canonical_json(token))`.
- [ ] Build `VerifiedApprovalSetBody` from sorted token digests, policy hash, threshold, eligible-set digest, request, intent, subject, authorizing-capability digest, signed proposal hash, proposal ID, creation time, and deadline. Compute `approval_set_hash = SHA256("chio.verified-approval-set.v1\0" || canonical_json(body))`.
- [ ] Make result independent of request token order.
- [ ] Preserve single-approval behavior when policy requires one.
- [ ] Add negotiated features `threshold_governed_approvals` and `governed_active_response_plan`. Reject threshold proposals, token sets, or response-plan bodies when the relevant feature is absent.
- [ ] Add `GovernedTransactionIntentBody::ActiveResponsePlan` with a protocol-owned `GovernedResponsePlanIntentBody` containing operator-capability id, digest and expiry, executor subject, canonical plan body, recomputed plan-body hash, target, ordered effects, expiry, and rollback binding. Verify that existing tool grants on internal server `chio.control-plane.active-response` cover every closed effect tool name.
- [ ] Ensure `GovernedTransactionIntent::binding_hash()` covers the complete normalized response-plan body and checked plan hash. Active defense sets approval tokens to that computed intent hash; it must not assign a raw `plan_hash` to `governed_intent_hash`.
- [ ] Expose the verified requirement, operator-capability binding, generic approval-only `AdmissionOperation`, and replay-safe approval-set result to active-defense heavy-action admission. Do not accept a caller-generated summary assertion.

**Negative tests:** `n-1`, duplicate signer with two tokens, duplicate token ID or digest, wrong request, wrong intent, wrong subject, wrong, expired, or revoked authorizing capability, missing effect grant, wrong internal server, capability digest mutation, denied decision, future proposal, expired proposal, token issued before proposal, token expiring after deadline, changed deadline, changed eligible-set digest, ineligible signer, untrusted proposal signer, untrusted token algorithm, oversized set, singular-plus-list ambiguity, response plan body/hash mismatch, and raw plan-hash substitution.

Commit: `feat(kernel): verify threshold governed approvals`

### Task 9: Make replay reservation and witness collection durable

**Files:**

- Modify the approval replay abstraction in `crates/kernel/chio-kernel/`
- Modify `crates/platform/chio-store-sqlite/src/approval_store.rs`
- Modify approval HTTP surfaces in `crates/platform/chio-http-core/`
- Modify product approval collectors that currently assume one approver

**Work:**

- [ ] Add `reserve_approval_set(operation_id, approval_set_hash, token_ids, token_digests, proposal_deadline)` as one atomic operation.
- [ ] Persist `reserved`, `committed`, and `cancelled` states owned by `operation_id`; cancelled entries remain tombstones.
- [ ] Reject a set if any member token ID, canonical token digest, or set hash belongs to another operation or was previously consumed.
- [ ] Retain replay rows through the proposal deadline.
- [ ] Store the signed proposal body by proposal ID, canonical request ID, intent hash, subject, authorizing-capability digest, policy hash, threshold, eligible-set digest, creation time, and deadline.
- [ ] Add unique `(proposal_id, approver_fingerprint)` and `(proposal_id, canonical_token_digest)` constraints.
- [ ] Forbid submitter approval when separation of duties is configured.
- [ ] Reject stale policy, changed intent, duplicate signer or digest, future or expired proposal, changed deadline, and terminal proposal updates.
- [ ] Collect and return the original `GovernedApprovalToken` values. Do not replace them with a collector assertion.
- [ ] Persist collector status before notifying waiters.

Adapt the transaction and test structure from Clawdstrike's `control-api` policy proposals, but use Chio token verification and canonical JSON. Add crash tests at proposal creation, vote append, threshold transition, replay reservation, and response delivery.

Commit: `feat(store-sqlite): persist threshold approval sets`

### Task 10: Share threshold algorithms with federation without weakening bilateral DSSE

**Files:**

- Modify `crates/trust/chio-federation/src/bilateral_dsse.rs` only to call a shared verifier where behavior remains byte-identical
- Add a new threshold DSSE profile only in a separate follow-up commit
- Modify `spec/schemas/chio-federation/v1/` and signed-artifact registry only when that profile exists

**Work:**

- [ ] Extract order-independent distinct-signer counting over an eligible key map.
- [ ] Keep `verify_dsse_envelope` and `verify_chio_bilateral_dsse_envelope` at exactly two required signatures.
- [ ] Add no negotiation bit until a distinct threshold predicate, schema, vectors, and verifier exist.
- [ ] If implemented, bind threshold DSSE to request hash, capability or lease, policy hash, subject, intent, time window, and nonce.
- [ ] Negotiate `threshold_dsse_invocation`; unnegotiated envelopes deny.

This task is optional for the first local threshold release.

Commit, only if implemented: `feat(federation): add negotiated threshold DSSE profile`

## Phase 4: runtime evidence boundary

### Task 11: Remove proof-carrying claims and harden the existing evidence path

**Files:**

- Modify normative text in `spec/PROTOCOL.md` and `spec/SECURITY.md`
- Add tests around `crates/platform/chio-control-plane/src/attestation/`
- Add tests around `crates/kernel/chio-runtime-core/src/validation/proof.rs`
- Do not create a proof-carrying request crate

**Work:**

- [ ] State that `RuntimeAttestationEvidence` is locally appraised evidence, not proof of arbitrary policy satisfaction.
- [ ] Preserve trusted-verifier, freshness, workload-identity, and assurance-tier checks.
- [ ] Prove malformed or stale evidence fails before budget admission.
- [ ] Prove a parity report with `accepted = true` and mismatches is rejected.
- [ ] Do not accept a bare parity report as authorization.
- [ ] If a request-carried parity binding is later required, first define a signed export envelope binding request ID, run ID, package and verifier hashes, signer, generation time, and expiry.

**Stop rule:** General proof-carrying authorization remains blocked until Transaction Passport evidence graph, membership verification, trusted-verifier policy, revocation, freshness, request binding, policy-version binding, and parity contracts exist in-tree with conformance vectors.

Commit: `docs(protocol): define runtime evidence authorization boundary`

## Phase 5: wire schemas and four-language generation

### Task 12: Update every authoritative and duplicated schema shape

**Files:**

- Modify `spec/schemas/chio-wire/v1/capability/token.schema.json`
- Modify `spec/schemas/chio-wire/v1/kernel/capability_list.schema.json`
- Modify `spec/schemas/chio-wire/v1/agent/tool_call_request.schema.json`
- Modify other embedded token shapes found by
  `rg 'budget_share_bps|max_invocations|RequireApprovalAbove|approval_budget_id' spec/schemas/chio-wire/v1`
- Add schemas for the aggregate and cumulative-approval root bindings, opaque supplemental-authorization carrier, threshold proposal, governed approval token extension, verified approval-set body, active-response governed intent body, and combined capture metadata
- Modify `spec/schemas/chio-wire/v1/capability/capabilities.schema.json`
- Register `chio.aggregate-budget-root.v1`, `chio.cumulative-approval-root.v1` and `chio.threshold-approval-proposal.v1` in `spec/schemas/registry.json` and the runtime known-schema set
- Regenerate `spec/schemas/MANIFEST.sha256`

**Schema requirements:**

- `aggregate_invocation_budget` has `additionalProperties: false`, required `scope` and `max_invocations`, scope enum, nonnegative integer maximum, and conditional family-root binding requirements.
- `RequireCumulativeApprovalAbove` has one strict negotiated definition with amount,
  currency, budget id/epoch, and conditional
  `cumulative_approval_root_binding`. Every duplicated capability/token schema
  references it. Delegable shapes require the signed binding; nondelegable direct
  shapes require it absent. The binding schema covers family root, root subject,
  scope, threshold, currency, budget id/epoch, expiry, signer/key epoch, and
  `additionalProperties: false`.
- Legacy `RequireApprovalAbove { threshold_units }` remains a separate per-request
  constraint and is never accepted as cumulative approval authority.
- Root binding and threshold proposal signatures use their domain-separated verifier contracts, not schema validation as a substitute for signature verification.
- Approval token arrays have an explicit maximum item count and reference one canonical token definition including `threshold_proposal_hash`.
- Threshold proposal and verified-set schemas require policy, eligible-set, request, intent, subject, authorizing-capability digest, creation-time, and deadline bindings.
- Active-response intent schema carries operator-capability id, digest and expiry, executor subject, canonical plan body, and checked plan-body hash.
- Combined capture metadata binds operation, hold, quota keys, the complete leaf-plus-delegation-ancestor-plus-supplemental revocation-set digest, budget commit, revocation commit, and leader epoch.
- Feature names remain string-keyed negotiation values.
- Rust serde names and JSON Schema names match exactly.
- Unknown fields continue to fail closed where the runtime type uses `deny_unknown_fields`.

**Generate and verify:**

```bash
cargo xtask codegen rust
cargo xtask codegen --lang python
cargo xtask codegen --lang ts
cargo xtask codegen --lang go
make codegen-check
```

**Language tests:**

- Rust generated-shape test and canonical fixture verification
- Python Pydantic parse, reject, and round trip
- TypeScript compile plus runtime validator fixtures
- Go parse, reject, and round trip
- One shared positive and negative fixture corpus consumed by all four languages

Commit: `feat(spec): define aggregate budgets and threshold approvals`

### Task 13: Preserve semantics through adapters

**Files:**

- Modify kernel request construction in MCP, A2A, ACP-Client, OpenAI, and Tower crates under `crates/protocol/`
- Modify browser, mobile, C++ FFI, Python, TypeScript, and Go SDK request models
- Modify cross-protocol fidelity reporting where a protocol cannot carry the extension

**Work:**

- [ ] Pass capability aggregate fields and the exact root binding byte-for-byte through native Chio envelopes.
- [ ] Pass the signed threshold proposal, complete approval token set, and typed governed intent to `ToolCallRequest`.
- [ ] Carry supplemental authorization only as opaque authenticated extension bytes. The kernel passes it to the installed verifier; adapters never deserialize it into a caller-controlled quota claim.
- [ ] Reject protocols that cannot authenticate these fields, or carry them in an authenticated Chio extension envelope.
- [ ] Never select the first approval and drop the rest.
- [ ] Never strip or reconstruct an aggregate root binding before verification.
- [ ] Preserve `AdmissionOperation.operation_id` through broker dispatch and downstream idempotency metadata where the target protocol supports it.
- [ ] Preserve combined capture metadata and authorizing-capability digests without inventing an adapter-local revocation check.
- [ ] Report truthful bridge fidelity for unsupported external protocol surfaces.
- [ ] Apply negotiated feature checks before adapter dispatch.
- [ ] Add end-to-end tests for native, MCP, A2A, and ACP-Client paths; add explicit rejection tests for any unsupported adapter.

Commit: `feat(protocol): carry aggregate budgets and approval sets`

## Phase 6: conformance, HA, and release gates

### Task 14: Add cross-implementation conformance vectors

**Files:**

- Modify `crates/tooling/chio-conformance/`
- Modify `crates/core/chio-adversarial-suite/`
- Add fixtures under the existing conformance fixture hierarchy
- Modify `spec/PROTOCOL.md`, `spec/SECURITY.md`, and threat coverage

**Required vector classes:**

- aggregate exhaustion across two grants
- family exhaustion across siblings with one identical CA-signed root binding
- forged root ID, root hash, issuer, subject, scope hash, expiry, signature, and binding digest
- maximum zero
- descendant family maximum lowering, raising, omission, or new-family creation
- all-or-nothing grant plus aggregate plus broker quota mutation
- supplemental verifier absent, wrong subject/request/destination, expired artifact, and caller-built quota claim rejection
- immutable maximum mismatch for an existing quota key
- revocation-versus-capture linearization under one combined authority
- idempotent event retry and conflicting event retry
- independent invocation capture and monetary release, capture, or reconciliation
- admission-saga crash recovery at every authority commit and saga-state write
- broker attempt registration, acknowledgement loss, and proof-nonce atomicity before budget authorization
- threshold success at exactly `n`
- sub-threshold, duplicate signer or token digest, replayed member, stale policy, wrong binding
- proposal future, expiry, deadline mutation, token outside proposal window, and eligible-set digest mutation
- verified approval-set domain separation and token-order invariance
- active-response plan body/hash mismatch and raw plan-hash substitution
- active-response operator-capability mutation, expiry, revocation, and approval-only admission recovery
- unnegotiated feature denial
- restart and HA race evidence
- signed receipt to store-event parity

Adapt test ideas from Clawdstrike durable proposal, witness, composite quota, and posture-persistence surfaces. Do not copy its non-atomic broker execution-count check.

Commit: `test(conformance): cover aggregate budgets and threshold approvals`

### Task 15: Add focused formal and concurrency checks

**Files:**

- Modify `crates/kernel/chio-kernel-core/src/formal_core.rs`
- Modify `crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs`
- Modify `formal/rust-verification/kani-public-harnesses.toml`
- Modify `.kani/harnesses.toml`
- Modify `formal/MAPPING.md`
- Modify `formal/proof-manifest.toml`
- Modify `crates/kernel/chio-kernel/tests/loom_concurrency.rs`
- Create `scripts/check-protocol-primitives-concurrency.sh`
- Modify `.github/workflows/ci.yml` to run the script and the PR-lane Kani manifest entries

**Properties:**

- captured counts never decrease
- an authorization mutates every applicable quota or none
- no execution is captured above a signed maximum
- an existing quota key cannot change its maximum
- a valid family binding maps every descendant to the same owner key and maximum
- a forged or changed family binding cannot satisfy the preservation predicate
- threshold count uses distinct eligible public keys
- one approval token ID participates in at most one consumed set
- token order does not change the set hash or decision
- compensation before dispatch never removes approval or nonce tombstones
- dispatch commitment prevents invocation reversal
- combined capture orders revocation and budget capture exactly once
- active-response approval reservation is operation-owned without budget or nonce participants

**Kani wiring:**

- [ ] Add pure bounded models and the harnesses `verify_composite_quota_all_or_nothing`, `verify_quota_maximum_immutable`, `verify_family_binding_preservation`, and `verify_threshold_distinct_signers`.
- [ ] Add every harness to `formal/rust-verification/kani-public-harnesses.toml` under `lanes.pr` and to `.kani/harnesses.toml` as `chio-kernel-core` PR entries.
- [ ] Add each harness to `formal/MAPPING.md` and update the covered symbols in `formal/proof-manifest.toml`.
- [ ] Run `scripts/check-mapping.sh` and `scripts/run-kani-manifest.sh --lane pr --crate chio-kernel-core`. An empty harness match is a failure.

**Loom wiring:**

- [ ] Add `protocol_primitives_` tests to the existing `loom_concurrency.rs` for last-unit contention, three-key all-or-nothing admission, immutable-maximum races, capture-versus-reverse, and idempotent compensation.
- [ ] Make `scripts/check-protocol-primitives-concurrency.sh` run `RUSTFLAGS="--cfg chio_kernel_loom" cargo test -p chio-kernel --test loom_concurrency protocol_primitives_`.
- [ ] Add the script to PR CI and the final gate. `loom` is already a `chio-kernel` dev dependency; preserve the existing `cfg(chio_kernel_loom)` check-cfg registration.

HA behavior still requires integration tests against the remote authority. Kani and loom do not support an HA correctness claim by themselves.

Commit: `test(formal): verify budget and threshold invariants`

### Task 16: Final release gate

Run:

```bash
cargo fmt --all -- --check
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
make codegen-check
bash scripts/check-mapping.sh
bash scripts/run-kani-manifest.sh --lane pr --crate chio-kernel-core
bash scripts/check-protocol-primitives-concurrency.sh
git diff --check
```

Then verify manually:

- [ ] no `chio-burn`, `chio-quorum`, or `chio-proof-carry` member exists
- [ ] no documentation says Chio lacks spend bounds
- [ ] no request-supplied family root, threshold, or eligible signer set exists
- [ ] no family owner derives authority from `delegation_chain.first().capability_id`; every family uses a verified CA root binding and immutable maximum
- [ ] no broker path reserves its supplemental quota twice
- [ ] no kernel path imports enterprise broker types or accepts a caller-built supplemental quota claim
- [ ] broker capture and relevant revocation writes share one linearizable authority; no sequential check-then-capture path claims production support
- [ ] invocation and monetary substates remain independently recoverable
- [ ] every multi-authority admission has a durable, fenced `AdmissionOperation`
- [ ] threshold timeout and verified-set hashes bind proposal times, policy, threshold, eligible set, request, intent, subject, authorizing-capability digest, and canonical token digests
- [ ] active-response approval binds the verified operator capability, typed response-plan governed intent, and generic approval-only admission operation, not a standalone plan hash
- [ ] no aggregate production path advertises `AdvisoryPosthoc` as hard enforcement
- [ ] no adapter silently drops the new fields
- [ ] all signed receipt projections match authoritative store rows
- [ ] Transaction Passport remains deferred rather than simulated by a signed claim
- [ ] singular approval compatibility has an explicit removal decision before v1 freeze

## Clawdstrike reuse and provenance rules

Allowed adapted inputs:

- Durable proposal transactions: `crates/services/control-api/src/routes/policies/proposals.rs` and `crates/services/control-api/migrations/021_policy_proposals.sql`
- Witness collection and deterministic ordering: Clawdstrike checkpoint and marketplace witness tests
- Composite quota key tests: broker constraint and posture-budget test patterns
- Persistence and restart tests: `crates/services/hushd/src/session/mod.rs`

Required adaptations:

- Chio canonical JSON, Chio public-key types, Chio trusted-authority resolution, Chio receipt metadata, and `BudgetStore` authority leases
- Atomic multi-key admission rather than Clawdstrike's read-then-execute `max_executions` check
- Fail-closed storage guarantees and explicit HA metadata

Forbidden until separately audited:

- Verbatim Spine implementation copied from files marked as adapted from AegisNet
- Any AegisNet-derived algorithm whose original source, license, attribution, and modification history have not been recorded

## Completion definition

This arc is complete only when aggregate issuance includes an authenticated CA family-root binding, quota maxima are immutable, grant, aggregate, and verified supplemental claims share one atomic hold, broker capture and revocation share one linearizable authority, invocation and monetary substates recover independently, and every multi-authority admission is coordinated by a durable fenced saga. Threshold approval must bind the signed proposal window, policy and eligible set, authorizing-capability digest, canonical token digests, typed governed intent, and replay tombstones; active response must use the same approval-only coordinator. The implementation must also be negotiated, adapter-complete, receipt-visible, four-language conformant, and wired into the checked-in Kani and loom gates. Documentation or in-memory demonstrations alone do not complete either primitive.
