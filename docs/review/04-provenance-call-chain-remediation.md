# Provenance / Call-Chain Remediation Memo

## Problem

ARC currently signs governed `call_chain` metadata without authenticating the
upstream lineage it describes. The result is a mismatch between what the
runtime actually proves and what the docs imply.

Today, a signed receipt can reliably prove:

- this kernel observed one request with one `request_id`
- this kernel evaluated one capability, policy set, and tool invocation
- this kernel preserved the caller-supplied governed intent and bound it to the
  receipt through `intent_hash`

Today, a signed receipt cannot reliably prove:

- that `parent_request_id` refers to a real authenticated upstream request
- that `parent_receipt_id` refers to a real signed upstream receipt
- that `origin_subject` and `delegator_subject` match the actual delegation
  path or session identity continuity
- that a governed call-chain spans sessions, kernels, or trust domains without
  tampering

The core defect is category confusion. ARC is signing a mixture of:

- local kernel observations
- validated runtime facts
- caller assertions about upstream provenance

as if all three had the same evidentiary strength.

## Current Evidence

The current implementation now has a real local provenance upgrade path, but it
still stops short of a durable cross-kernel authenticity model.

- `crates/arc-core-types/src/capability.rs` still defines the raw
  `GovernedCallChainContext`, but receipts and reports now carry
  `GovernedCallChainProvenance` with an explicit evidence class:
  `asserted`, `observed`, or `verified`.
- `crates/arc-kernel/src/kernel/mod.rs`
  `validate_governed_call_chain_context` now rejects empty fields, rejects
  self-referential parent requests, binds nested flows to the locally
  authenticated parent request when present, enforces delegator-subject
  consistency against capability lineage, and optionally validates a signed
  upstream delegator proof for coherence, signature, and time bounds.
- `crates/arc-kernel/src/receipt_support.rs` upgrades
  `governed_transaction.call_chain` from `asserted` to `observed` when the
  kernel can corroborate local parent request lineage, local parent receipt
  linkage, or capability-lineage subjects, and upgrades to `verified` only when
  a signed upstream delegator proof also validates.
- `crates/arc-kernel/src/request_matching.rs`
  `begin_child_request_in_sessions` still only records parent request lineage
  inside one live kernel session.
- `crates/arc-kernel/src/session.rs`, `crates/arc-core-types/src/session.rs`,
  and `crates/arc-kernel/src/kernel/session_ops.rs` now mint signed session
  anchors, track local request lineage, and persist those records for local
  session continuity and nested-flow provenance.
- `crates/arc-store-sqlite/src/receipt_store/support.rs` and
  `crates/arc-store-sqlite/src/receipt_store/reports.rs` now keep the
  call-chain evidence class visible and fail closed on sender binding:
  asserted call-chain provenance does not count as delegated sender-bound truth.
- `crates/arc-core-types/src/capability.rs` and
  `crates/arc-kernel/src/capability_lineage.rs` now participate in governed
  call-chain corroboration, but signed receipt-lineage statements are still not
  emitted pervasively enough to make every child edge independently portable.
- `crates/arc-kernel/src/receipt_support.rs`
  `build_child_request_receipt` still records local `parent_request_id` for
  child receipts, but parent/child receipt linkage remains implicit rather than
  a separate signed lineage artifact.

The repo therefore has:

- typed governed call-chain provenance classes
- local parent-child request bookkeeping
- local parent receipt lookup
- capability lineage corroboration
- fail-closed authorization-context projection for asserted provenance

but not durable authenticated end-to-end provenance linkage across sessions,
kernels, and trust domains.

## Why Claims Overreach

The current docs and reviewer-facing materials say or imply that ARC can prove
delegated call-chain provenance, trace governed actions back through authority,
and surface delegated transaction context as review-grade truth. That is too
strong for the current runtime.

The overreach is structural:

- `call_chain` still enters the system as caller or approval-bound context and
  becomes stronger only when ARC can corroborate it locally.
- a receipt signature proves ARC signed the metadata and any corroborated local
  evidence ARC checked, but it still does not prove missing parent artifacts,
  session continuity, or replay-safe cross-kernel handoff.
- the authorization-context report now preserves the evidence class and no
  longer upgrades asserted lineage into sender-bound truth, but it still lacks
  complete outward request-lineage and receipt-lineage evidence coverage to
  support stronger public claims.
- local child-request lineage and governed call-chain lineage still are not one
  durable provenance DAG.
- session continuity is now represented locally through session anchors and
  request-lineage records, but that proof is not yet carried end to end across
  every outward surface or cross-kernel handoff.
- there is no replay-protected continuation artifact carrying parent receipt
  hash, session anchor, and delegation bindings across kernels.

The honest claim today is narrower:

- ARC can preserve caller-supplied delegated transaction context as `asserted`
  provenance inside a signed receipt.
- ARC can upgrade that provenance to `observed` from local parent request or
  parent receipt evidence plus capability-lineage corroboration, and to
  `verified` when a signed upstream delegator proof matches the validated
  capability lineage.
- ARC can prove local request execution, local receipt integrity, and local
  session/request continuity through persisted session anchors and
  request-lineage records.
- ARC cannot yet prove every parent-child receipt edge or cross-kernel handoff
  from a complete set of signed lineage artifacts.

## Phase 1 Execution Order

The provenance upgrade order now present in the repo is:

1. `asserted`
   - caller-supplied `call_chain` context is preserved, but it is only caller
     assertion at this stage.
2. `observed`
   - ARC upgrades the same context when it can corroborate one or more local
     facts:
     live-session parent request lineage, locally present parent receipt
     linkage, or capability-lineage subject matches.
3. `verified`
   - ARC upgrades only when a signed upstream delegator proof also validates
     against the asserted context and the executing capability lineage.
4. report gate
   - the authorization-context projection sets
     `delegatedCallChainBound = true` only for corroborated provenance;
     asserted-only lineage remains visible but non-normative.

What is still missing after this order:

- signed receipt-lineage statements
- consistent outward session-anchor and request-lineage references
- replay-protected cross-kernel continuation tokens and their trust policy

## Target End-State

ARC should move to a typed provenance model with explicit evidence classes.

Every provenance field used in receipts, enterprise reports, federation
artifacts, or reviewer packs must be labeled as exactly one of:

- `asserted`: provided by the caller or upstream system and only syntax-checked
- `observed`: generated by the local kernel from facts it directly controls
- `verified`: checked against signed parent artifacts, local session state, and
  capability lineage

The strong public claim should only attach to `observed` and `verified`
provenance.

In the target state, ARC can honestly claim:

- a local child receipt is linked to a real parent request the kernel observed
  in the same session
- a governed receipt with verified call-chain metadata is linked either to a
  verified parent receipt or to a signed continuation artifact issued by a
  trusted upstream kernel or operator
- session continuity is bound to an authenticated session anchor, not just a
  mutable `session_id` string
- delegator and origin subjects are either derived from verified lineage or
  checked against capability/delegation evidence
- enterprise authorization projections only emit delegated call-chain truth
  when the lineage edge is verified

ARC should not claim more than this:

- a receipt does not prove real-world side effects outside kernel observation
- a receipt does not prove the honesty of a foreign operator unless ARC has
  explicit trust anchors and verifies that operator's signed artifact
- a receipt does not prove future settlement or liability consequences by
  itself

## Required Runtime/Data-Model Changes

### 1. Split Raw Call Context From Verified Provenance

Do not continue using one `GovernedCallChainContext` shape for both caller
input and signed receipt truth.

Introduce a versioned provenance model, for example:

- `AssertedCallChainContext`
- `ObservedLocalLineage`
- `VerifiedCallChainContext`

The receipt should only carry `VerifiedCallChainContext` in the strong
`governed_transaction` block. If ARC wants to preserve raw caller input for
debugging or forensics, store it separately under a clearly weaker name such as
`asserted_context`.

This is the key semantic repair. Without it, every later report or proof
surface will keep conflating assertion with proof.

### 2. Add Session Anchors

ARC needs a stable signed anchor for the authenticated session context.

Add a `SessionAnchor` artifact generated when a session becomes active and
rotated whenever the auth context materially changes. The anchor should bind:

- `session_id`
- `agent_id`
- transport kind
- normalized `SessionAuthContext`
- a canonical hash of the auth method details
- token fingerprint or proof-binding material when applicable
- auth epoch / version
- `issued_at`
- kernel signer

Every receipt should reference the active `session_anchor_id` or
`session_anchor_hash`.

This fixes two gaps:

- lineage can now refer to authenticated session identity rather than bare
  `session_id`
- session reuse and auth-context drift become explicit, versioned events rather
  than silent mutable state

### 3. Add Request-Lineage Records

Persist request lineage as first-class kernel state rather than inferring it
later from receipt JSON.

Add a request-lineage table keyed by `request_id` with:

- `request_id`
- `session_anchor_id`
- `parent_request_id`
- operation kind
- capability id
- subject key
- issuer key
- intent hash when present
- lineage mode: `local_child`, `continued`, `root`
- start timestamp

For local nested flows, the kernel can mark the parent edge as `observed`
because it directly checked that the parent request existed and was in-flight.

### 4. Add Signed Receipt-Lineage Statements

One receipt alone cannot always carry complete parent receipt linkage because
parent and child receipts may finalize at different times. Do not force this
into the receipt body if it creates circular dependencies.

Instead, add a signed `ReceiptLineageStatement`, persisted and checkpointed
alongside receipts, with fields like:

- `statement_id`
- `parent_receipt_id`
- `child_receipt_id`
- `parent_request_id`
- `child_request_id`
- `parent_session_anchor_id`
- `child_session_anchor_id`
- lineage relation kind
- issuance timestamp
- kernel signer

This allows ARC to prove:

- local child receipt to parent receipt linkage
- post-facto parent binding once both receipts exist
- multi-hop receipt DAGs without mutating existing signed receipts

Queries and reviewer packs should consume lineage statements, not infer parent
truth from freeform metadata strings.

### 5. Add Cross-Kernel Continuation Tokens

For provenance that crosses session or kernel boundaries, require a signed
continuation artifact instead of raw `call_chain` strings.

Add a `CallChainContinuationToken` or similar artifact containing:

- `token_id`
- `chain_id`
- upstream kernel or operator signer
- `parent_request_id`
- optional `parent_receipt_id`
- parent receipt hash when available
- `parent_session_anchor_id`
- `current_subject`
- `delegator_subject`
- `origin_subject`
- parent capability id
- optional delegation-link id or hash
- child request binding or governed intent hash binding
- target server/tool or audience binding
- `issued_at`
- `expires_at`
- optional nonce / replay binding

The child kernel should accept strong governed call-chain claims only when:

- the continuation token verifies against a trusted signer
- its subject, capability, session anchor, and intent binding match the actual
  child request
- any supplied parent receipt verifies and matches the token
- the token is fresh and not replayed

This is the main bridge from local provenance to cross-boundary provenance.

### 6. Bind Call-Chain Provenance To Delegation Lineage

The governed call-chain must stop being independent from capability lineage.

Require the runtime to enforce:

- the executing capability subject equals the current subject in provenance
- `delegator_subject` matches the verified parent subject or delegation source
- `origin_subject` is derived from the root of the verified lineage rather than
  accepted as a free caller string
- if a parent capability id or delegation-link hash is present, it must match
  the actual capability lineage stored or presented
- any governed delegated call that cannot be reconciled against capability
  lineage is denied or downgraded to `asserted`

This makes the call-chain claim subordinate to the actual authorization chain.

### 7. Unify Local Child Receipts And Governed Call Chains

ARC currently has:

- child-request lineage for sampling/elicitations
- governed call-chain metadata for tool actions

These should be two projections of one provenance DAG, not two unrelated
systems.

Unify them under one runtime lineage model:

- nodes: requests, receipts, session anchors, capabilities
- edges: parent request, receipt lineage, continuation, delegation source,
  session continuation

Then expose different projections:

- child-request lifecycle view
- governed transaction provenance view
- enterprise authorization-context view
- cost-attribution / underwriting lineage view

### 8. Tighten Receipt Metadata Semantics

Redefine what the strong receipt metadata means.

Recommended rule:

- `governed_transaction.call_chain` means `verified_call_chain`
- if ARC has only caller assertions, store them in
  `governed_transaction.asserted_context.call_chain`
- reviewer/export/report surfaces must never collapse `asserted` into
  `verified`

Also add explicit provenance basis fields, for example:

- `lineageEvidenceClass`
- `lineageSource`
- `continuationTokenId`
- `receiptLineageStatementId`
- `sessionAnchorId`

That lets downstream consumers know exactly what was checked.

### 9. Fail Closed In Reports And Hosted Auth

The current report path already fails closed on malformed projections. Extend
that to authenticity.

`/v1/reports/authorization-context` and related reviewer packs should refuse to
emit `delegatedCallChainBound = true` unless the record is backed by:

- local observed parent-child lineage, or
- a verified continuation token, or
- a verified parent receipt plus a valid receipt-lineage statement

Anything else should either:

- omit delegated call-chain fields, or
- emit them only in an explicitly `asserted` diagnostics section that is not
  part of the normative profile

### 10. Migration Strategy

Do not reinterpret old receipts as stronger than they were.

For existing v1 receipts:

- classify old `call_chain` metadata as `asserted` by default
- allow local backfill to upgrade only when ARC can reconstruct verified
  lineage from stored request, receipt, and session records
- keep enterprise profile emission fail-closed for unverifiable legacy rows

This avoids retroactive claim inflation.

## Proof/Spec Changes

### 1. Add A Normative Provenance Model To The Spec

Update `spec/PROTOCOL.md` so provenance is no longer described as one generic
metadata block. Define:

- provenance node types
- provenance edge types
- evidence classes: `asserted`, `observed`, `verified`
- allowed transitions between those classes
- what must be signed
- what must be derived
- what may remain caller-supplied and non-normative

### 2. Add New Safety Properties

The current protocol properties do not capture lineage authenticity. Add
explicit properties such as:

- `P6` local parent-link soundness: a verified local parent edge implies the
  parent request existed in the same authenticated session when the child was
  created
- `P7` receipt-lineage soundness: a verified receipt-lineage edge implies both
  receipts verify and the edge was signed by a trusted kernel
- `P8` session continuity soundness: a continued request/receipt can only claim
  session continuity through a valid session anchor and continuation artifact
- `P9` delegation/provenance consistency: verified call-chain subjects and
  parent capability references are consistent with capability lineage
- `P10` report truthfulness: enterprise projections never label `asserted`
  lineage as `verified`

### 3. Narrow The Receipt Claim In The Spec

The spec should explicitly say:

- receipts prove kernel-observed evaluation events
- lineage statements prove authenticated linkage between those events
- continuation tokens prove authenticated upstream context transfer
- none of these alone prove external real-world completion beyond the kernel's
  observation boundary

This should also be reflected in `README.md`, `docs/AGENT_ECONOMY.md`,
`docs/VISION.md`, and partner/release proof packages.

### 4. Formalize The Right Layer

Do not try to jump straight to a giant end-to-end theorem.

Formalize a smaller core:

- provenance graph well-formedness
- edge authenticity rules
- monotonic downgrade rule: `verified -> asserted` is allowed only by
  explicitly changing class, never silently
- delegation/provenance consistency invariants
- replay and expiry checks for continuation tokens

Only after the runtime enforces these rules should Lean or differential-proof
claims mention provenance authenticity.

### 5. Version The Schemas

Introduce versioned schemas for:

- `arc.session_anchor.v1`
- `arc.receipt_lineage_statement.v1`
- `arc.call_chain_continuation.v1`
- `arc.governed_transaction_receipt_metadata.v2`
- `arc.oauth.authorization-context-report.v2` if the projection semantics
  change materially

Versioning matters because the old `call_chain` shape is too weak to extend
implicitly.

## Validation Plan

### 1. Unit Tests

Add contract tests for:

- session-anchor hashing and signature verification
- continuation token signing, expiry, and replay protection
- delegation/provenance consistency checks
- receipt-lineage statement verification
- downgrade handling from `verified` to `asserted`
- rejection of mismatched parent receipt hash, subject, capability id, or
  session anchor

### 2. Kernel Integration Tests

Add kernel tests that cover:

- local nested child request produces an observed parent edge
- parent receipt finalization emits a signed receipt-lineage statement
- mismatched parent request in same session is rejected
- mismatched `delegator_subject` or `origin_subject` is rejected
- continuation token bound to one intent hash cannot be replayed for another
  governed action
- session auth rotation invalidates stale continuation artifacts

### 3. Cross-Kernel / Cross-Operator Tests

Add distributed tests with two kernels:

- upstream kernel issues continuation token, downstream kernel verifies it
- downstream request fails when parent signer is untrusted
- downstream request fails when parent receipt hash mismatches
- downstream request fails when child capability lineage does not match the
  continuation token's delegation bindings
- replay across nodes is rejected

### 4. Report / Projection Tests

Strengthen `crates/arc-cli/tests/receipt_query.rs` so report emission is gated
on authenticity, not just field presence.

Required negative cases:

- non-empty but unverifiable call-chain data
- parent receipt referenced but missing
- parent receipt present but wrong signer/hash
- session-anchor mismatch
- delegation-link mismatch
- legacy asserted-only rows must not produce
  `delegatedCallChainBound = true`

### 5. Adversarial Tests

Add threat-driven tests for:

- caller invents `parent_request_id`
- caller invents `parent_receipt_id`
- caller reuses a valid continuation token on a new request
- parent receipt exists but belongs to a different subject/session
- child tries to escalate from one delegator to another
- stale session continuation after auth narrowing

### 6. Qualification / Release Gates

Do not restore strong provenance claims until the release gate includes:

- kernel provenance regressions
- cross-kernel continuation regressions
- authorization-profile fail-closed regressions
- migration/backfill regressions
- reviewer-pack truthfulness regressions

## Milestones

### M1. Claim Hygiene And Schema Freeze

- narrow public docs immediately
- define provenance evidence classes
- freeze current schema shapes for session anchor, continuation token, and
  receipt-lineage statement

### M2. Local Lineage Foundation

- add request-lineage persistence
- add session anchors
- add observed local parent-child lineage
- emit receipt-lineage statements for local nested flows

### M3. Delegation And Receipt Consistency

- bind provenance validation to capability lineage
- require subject/delegator/origin consistency
- add receipt-reference verification and hash/signature checks

### M4. Cross-Kernel Continuation

- ship signed continuation tokens
- add replay protection and expiry handling
- ship cross-kernel trust-anchor configuration and verification

### M5. Report And Hosted Auth Hardening

- require corroborated observed or verified lineage for sender-bound delegated
  call-chain claims
- expose asserted lineage only in non-normative diagnostics
- update reviewer packs and partner proof docs

### M6. Proof And Qualification

- update protocol safety properties
- add formal model for provenance authenticity core
- make provenance authenticity part of release qualification

Current repo state:

- `M1` is real for receipt and report semantics: evidence classes ship and
  asserted provenance no longer counts as delegated sender-bound truth.
- `M2` is materially real for local provenance: session anchors and
  request-lineage records are emitted and persisted for local session and
  nested-flow lineage, but outward references are not yet complete everywhere.
- `M3` is partially real: capability-lineage subject consistency and signed
  upstream delegator proof validation exist, and the store can persist
  receipt-lineage statements, but the kernel does not yet emit a complete
  signed receipt-lineage proof for every child edge and parent-receipt hash
  verification remains incomplete.
- `M4` is partially real: continuation-token shapes and validation hooks exist,
  but replay-safe cross-kernel trust distribution and qualification remain open.
- `M5` is materially real for authorization-context truthfulness, but
  reviewer-pack and partner-proof semantics still depend on the missing
  artifacts above.

## Acceptance Criteria

The provenance/call-chain claim is only defensible once all of the following
are true:

- ARC no longer treats caller-supplied `call_chain` strings as equivalent to
  verified provenance.
- every strong call-chain claim in a signed receipt is backed by either local
  observed lineage or a verified upstream continuation artifact.
- every governed receipt can identify the authenticated session anchor under
  which it was admitted.
- any emitted `delegator_subject` and `origin_subject` are derived from or
  validated against actual capability/session lineage rather than accepted as
  unchecked strings.
- enterprise authorization reports set `delegatedCallChainBound = true` only
  for corroborated observed or verified lineage.
- an independent verifier can reconstruct a child-to-parent lineage edge from
  signed artifacts without trusting mutable operator prose.
- legacy unverifiable rows are downgraded to `asserted` rather than silently
  upgraded.
- replay, stale continuation, subject mismatch, capability mismatch, and
  session-anchor mismatch all fail closed.

## Risks/Non-Goals

### Risks

- provenance will add storage and index pressure because request, session, and
  lineage artifacts become first-class records
- parent/child finalization ordering is tricky; receipt-lineage statements are
  necessary partly because one receipt may not exist yet when another is signed
- cross-kernel provenance requires explicit trust-anchor management and replay
  controls
- migration will expose how much existing evidence is only asserted, which may
  temporarily reduce what the product can claim

### Non-Goals

- proving the external real-world side effect occurred beyond what the kernel
  observed
- building a global transparency log or total ordering for all provenance
  events
- retroactively upgrading old receipts without actual backing evidence
- inferring inter-organization trust automatically from visibility or discovery
- collapsing receipts, lineage statements, continuation tokens, and settlement
  records into one artifact type

The right target is narrower and stronger: ARC should become able to prove
authenticated lineage edges between governed actions, receipts, sessions, and
delegation state. That is enough to make the provenance claim real without
pretending to prove more than the runtime actually controls.
