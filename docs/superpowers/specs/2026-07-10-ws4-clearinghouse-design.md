# WS4 Design: Chio Clearinghouse

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see `2026-07-10-agent-economy-program-design.md`)
- Depends on: `chio_credit::obligation`, an authoritative participant mapping,
  WS1 for dispatch, the 2026-07-12 FROST quorum substrate through Phase 3, and
  the external economic-state continuity substrate before round-finalization
  activation
- Claim track: implementation (signed netting intent and reconciliation evidence, never settlement truth)
- Branch: `chio/ws4-clearinghouse` off `main`

## Goal

Reserve a complete single-currency set of canonical obligations and derive a
deterministic, smaller set of settlement intents. V1 cancels bilateral flows,
computes each participant's net balance, and canonically matches debtors to
creditors. It does not treat kernel signers as creditors, ingest the same debt
from two report families, mutate intent after signing, or describe netting as
custody or finality.

## Ground truth and prerequisites

- Exposure-ledger rows and IOU envelopes can describe the same receipt. Reading
  both directly double counts one debt.
- `IouEnvelope.issuer_key` is a kernel signer, not a creditor. Participant and
  destination identity cannot be inferred from it or from `tool_server`.
- A bounded exposure report can omit older obligations. A report at its item
  limit is not proof that an epoch input is complete.
- Cycle cancellation alone is not netting. For `A -> B -> C`, there is no
  cycle, yet balances permit the equivalent `A -> C` settlement.
- A settlement packet cannot contain empty reconciliation fields that are later
  filled without invalidating its signature.

WS4 therefore has two hard prerequisites:

1. The shared producer emits one immutable
   `chio_credit::obligation::ObligationAtom` per receipt-backed debt. It
   deduplicates source artifacts before WS4 and preserves the authoritative
   debtor, payee-bound creditor, amount, and currency. Current settlement
   lifecycle, version, and
   `chio_credit::obligation::ObligationDisposition` are separate authenticated
   records owned by the same module and store contract.
2. A configured participant authority emits a signed, versioned participant
   snapshot that maps every debtor and creditor identity/key to one canonical
   participant id and settlement destination. WS4 has no fallback mapping and
   does not defer this requirement to a later workstream.

## In scope

1. A pure `chio_credit::clearing` module for deterministic v1 netting.
   `chio-credit` already owns the canonical obligation and v1 adds no crate.
2. Exactly one currency per round.
3. Bilateral cancellation followed by participant-balance computation and
   deterministic debtor-to-creditor matching.
4. Transactional input reservation using the shared
   `clearing_reserved` disposition.
5. Immutable round and settlement-intent artifacts, plus separate immutable
   reconciliation artifacts.
6. Complete input/output manifests, disputes, quorum-gated finalization,
   schemas, public verifier coverage, and ladder registration. Artifacts may land
   before the FROST prerequisite; no finalization becomes dispatchable without it.

## Out of scope

- Direct ingestion of exposure reports or IOU envelopes, cross-currency
  conversion, FX evidence, and mixed-currency totals.
- Live participant discovery, inferred organization/key mappings, or a
  participant snapshot signed only by the round proposer.
- Fund movement, custody, on-chain dispatch, new Solidity, and any settlement
  finality claim.
- A clearing network, live-state consensus, or distributed-linearizable truth.
- Partial, paginated, capped, or "best available" round input.

## Design

### Canonical input and reservation

`compute_netting_round` accepts:

- `round_id`, `epoch`, `algorithm_version`, and one `currency`;
- a trusted participant-snapshot body and digest;
- a complete canonical atom manifest; and
- reservation proofs for every atom.

Every atom must:

- have a unique `obligation_id` and canonical digest;
- bind one signed receipt and authoritative payee-bound creditor;
- match the round currency;
- have a separate settlement-lifecycle record that is currently outstanding at
  the submitted version; and
- have a separate `chio_credit::obligation::ObligationDisposition` changed from
  `per_call` to `clearing_reserved { round_id }` in the shared external
  round/obligation batch.

The control plane first reads candidate versions and constructs the complete
signed round core and replay input. One SQLite transaction stages that exact body,
every candidate reservation and a `RoundLifecycleRecord` in `reserved` state, but
does not expose the reservations. It then advances one external
`EconomicStateAnchor` batch covering the round plus every obligation disposition,
and finalizes the local projection. Only that anchored batch makes the
reservations authoritative. If any local compare-and-swap, external expected head
or row insert fails, no admitted round becomes executable. Exact duplicate ids,
even with equal bytes, reject the submitted manifest so the caller cannot make
cardinality ambiguous. An atom in `assigned` or `channelized` is ineligible.

Each reservation proof binds the atom digest, old and new versions, prior and
new disposition, round id, and authority signature. The input manifest commits
to the sorted list and its count. A source must provide a closed epoch range,
start/end checkpoints, and completeness proof. Any `has_more` condition,
unconsumed cursor, count mismatch, missing range position, or capped report
rejects the round.

`chio_credit::clearing` owns the backend-neutral lifecycle contract and
`chio-store-sqlite` implements it:

```rust
pub enum RoundLifecycleState {
    Reserved,
    Proposed,
    Finalizing,
    Finalized,
    Dispatching,
    Reconciling,
    Satisfied,
    Aborting,
    Aborted,
    Incident,
}

pub struct RoundLifecycleRecord {
    pub round_id: String,
    pub round_core_digest: String,
    pub input_manifest_digest: String,
    pub state: RoundLifecycleState,
    pub row_version: u64,
    pub fence: u64,
    pub output_manifest_digest: Option<String>,
    pub finalization_digest: Option<String>,
    pub abort_digest: Option<String>,
    pub first_dispatch_operation_id: Option<String>,
    pub continuity_head_digest: String,
}
```

The store retains the complete canonical replay input and external state batch,
not only roots, so boot recovery can reconstruct the anchor-authoritative state.
Every transition is an authority-authenticated local stage followed by the
external round-plus-obligation compare-and-swap and exact local finalization.
Readiness requires the local head digest to equal the external head. Age is never
reservation-release authority.

### Deterministic v1 algorithm

All sorting compares canonical participant-id bytes. All addition,
subtraction, and signed balance conversion is checked. Overflow rejects the
round, and every emitted amount must convert exactly to
`MonetaryAmount.units: u64`. There is no saturating result or
`arithmetic_saturated` success state.

1. Verify the participant snapshot, atom digests and source receipt signatures,
   completeness proof, reservation proofs, exact currency, unique ids, and
   canonical order.
2. Aggregate directed amounts by ordered pair
   (`debtor`, `creditor`) with checked `u128` sums.
3. Bilateral cancellation: for each unordered pair, subtract the smaller
   direction from the larger and retain at most one residual direction.
4. Compute each participant balance from the residual graph:
   credits received minus debts owed. Zero balances drop. Partition negative
   balances into debtors and positive balances into creditors.
5. Check that absolute total debtor balance equals total creditor balance.
6. Sort debtors and creditors canonically. Match the first debtor to the first
   creditor for the minimum remaining amount, advance each exhausted side, and
   repeat until both lists are empty.
7. Emit one immutable settlement intent per non-zero match and one participant
   statement per participant. Also emit a deterministic transformation witness
   that lets a verifier replay how every input atom contributed to bilateral
   cancellation, participant balances, and the final intents.

This deliberately reduces `A -> B -> C` to `A -> C` when the values permit.
The canonical greedy match is not claimed to minimize rail fees under every fee
model; it is deterministic, conserves balances, and emits at most
`debtors + creditors - 1` intents.

### Artifacts

All artifacts are RFC 8785 canonical JSON with `deny_unknown_fields`,
versioned schema identifiers, and signatures over immutable bodies.

- `chio.clearing.netting-round-core.v1` binds the round, epoch, trusted clearing
  governance scope id, currency, algorithm, participant snapshot digest, complete input manifest root and
  count, reservation-proof root, dispute window, and generation time. Its
  `round_core_digest` is computed before any output and is the only round
  digest bound by statements and intents.
- `chio.clearing.participant-statement.v1` binds one participant's gross debit,
  gross credit, bilateral adjustment, final net balance, contributing atom
  digests, and `round_core_digest`.
- `chio.clearing.settlement-intent.v1` binds `intent_id`,
  `round_core_digest`, debtor and creditor participant ids, the authoritative
  destination from the participant snapshot, amount and currency, contributing
  reservation root, and dispatch idempotency key. It contains no mutable
  reconciliation or external transaction field. The derived
  operation-specific economic effect-slot id is bound separately before dispatch.
- `chio.clearing.output-manifest.v1` binds `round_core_digest`, the complete
  participant-statement, settlement-intent, and atom-transformation roots and
  counts. Those leaves bind only the core, so this digest graph is acyclic.
- `chio.clearing.participant-acceptance.v1` binds the output-manifest digest,
  participant statement digest, participant id, and acceptance signature.
- `chio.clearing.round-finalization.v1` binds `round_core_digest`,
  output-manifest digest, complete participant-acceptance root and count, and
  external lifecycle-head digest, version and fence. Its action-body digest excludes the quorum
  proof. The detached `chio.frost.authorization.v1` must use domain
  `chio.frost.clearing-round-finalize.v1`, registered ladder action class
  `clearing.round_finalize`, `scope_id` equal to the round core's trusted
  governance scope, `resource_id` equal to round id, and bind that action digest,
  active roster digest, key epoch, authorization-slot id, lifecycle version, and fence.
  Nothing upstream binds the finalization digest.
- `chio.clearing.settlement-reconciliation.v1` is emitted later and separately.
  It binds the immutable intent digest, WS1 settlement outcome digest, external
  references, observed status, attempt number, and observation time.
- `chio.clearing.zero-intent-reconciliation.v1` is a distinct signed
  reconciliation variant for a finalized round whose output manifest proves
  `settlement_intent_count == 0`. It binds the finalization digest, empty intent
  root, complete input-reservation root, atom ids and expected lifecycle
  versions, outcome `netted_without_rail`, and the fresh lifecycle-transition
  authority digest. It cannot represent a non-empty round.
- `chio.clearing.round-abort.v1` binds the round core, optional output-manifest
  digest, complete reservation root and expected disposition versions, a closed
  reason enum, external lifecycle source-head digest, version and next fence, a durable RFC-0003
  operation proof that no round intent was ever dispatched, and fresh
  `clearing.round_abort` capability/policy/guard authority.
  The configured disposition authority signs it; a proposer signature or an
  empty external-reference field is insufficient.
- The atom-transformation manifest is a complete deterministic witness, not a
  second obligation record. Each row references an immutable atom digest and
  the bilateral, balance, and intent steps that transformed it. Replaying all
  rows must reconstruct both the complete input root and every output intent.
- `chio.clearing.round-dispute.v1` binds `round_core_digest`, optional
  output-manifest digest, disputing participant, disputed leaf digests, reason
  code, and evidence references.

A statement or intent alone is not a complete round proof. Verification
requires its inclusion in the signed output manifest and a valid finalization
that includes every participant acceptance.

### Lifecycle and exclusive routing

1. Build and sign the complete round core, stage all atom reservations plus the
   exact core/replay/manifest/lifecycle locally, advance the bounded external
   round-plus-obligation batch to `reserved`, then finalize locally. Recovery can
   therefore always name the anchor-authoritative round that owns a reservation.
2. Stage and externally compare-and-swap `reserved -> proposed`, compute statements, intents, and
   transformation rows against `round_core_digest`, then persist the signed
   output manifest over their roots.
3. Open the declared dispute window. Every affected participant signs its
   statement and the output-manifest digest, thereby accepting the v1 setoff
   and counterparty substitution for this round. A missing participant
   acceptance, valid in-window dispute, or incomplete governance quorum blocks
   finalization.
4. Finalization stages and externally advances `proposed -> finalizing` at the
   expected anchored version and fence, finalizes that local projection, then
   obtains the FROST authorization over the proof-free finalization body. A
   second external state batch consumes the permanent completed authorization
   slot, advances `finalizing -> finalized`, binds the proof and finalization
   digests, and preserves every obligation reservation head. Local finalization
   follows that anchor CAS. This is the single FROST-consumption point. A group signature
   proves threshold group authorization, not the exact signer subset. Individual
   participant acceptances remain attributable evidence and are not a fallback.
   With no production FROST substrate, the transition returns
   `UnsupportedQuorum` and remains non-dispatchable.
5. Abort competes through the same external lifecycle head. It may stage
   `reserved|proposed -> aborting` only after rechecking zero dispatch. A
   `finalizing` round may enter `aborting` only after its FROST session is durably
   cancelled and burned, the fence advances, and zero dispatch is rechecked.
   One external batch binds the signed abort, releases every exact obligation
   reservation head, and transitions the round to `aborted`; local rows finalize
   only afterward. `finalized` and later states cannot abort.
6. For each immutable intent, WS1 first derives and persists its own RFC-0003
   `AdmissionOperation::Prepared` with exact request binding and expected handoff
   version/fence. Only then may an external batch create that operation's `Ready`
   effect slot. For the first intent the same batch advances `finalized ->
   dispatching` and records `first_dispatch_operation_id`; later intent batches
   require and preserve that dispatching generation and every reservation. Each
   attempt requires separate fresh WS1 settlement capability/policy/guard
   authority; it does not consume the finalization proof again. WS1 then commits
   the matching admission handoff state, and only the winner of the external
   effect-slot `Ready -> DispatchCommitted` CAS may call the rail. Recovery uses
   authenticated rail status or qualified same-key idempotency; otherwise that
   intent remains unknown/reserved and is never resubmitted. Per-call,
   assignment, and channel settlement must skip all `clearing_reserved` atoms.
7. Each attempt emits a separate reconciliation artifact and advances its effect
   slot in the same external round/obligation batch: exact settled evidence moves
   it to `Completed`; verified permanent no-effect moves it to `NoEffect`; and
   effect-possible ambiguity moves it to `Unknown` plus round `Incident` while
   preserving every reservation. A `NoEffect` attempt may be followed only by a
   freshly authorized operation and new effect slot for the same immutable
   intent. Reconciliation never edits the intent.
8. Only after every round intent has at least one exact `Completed` settled slot
   and no live/unknown attempt does one external batch
   advance the round and every input obligation's separate settlement lifecycle
   to satisfied, followed by local finalization. The
   immutable atoms do not change. Once any dispatch begins, failure creates a
   reconciliation incident and the remaining intents retry idempotently; no input
   returns to `per_call` and no carried-forward copy is created.

Boot recovery is claimed by a lease-fenced owner and reads the external
continuity heads before trusting the stored replay input. Readiness stays false
until the local round and every obligation head exactly match. An anchor-ahead
projection is reconstructed from retained canonical state; an unanchored stage
may retry or be discarded; divergence or anchor outage denies serving. A
`reserved` or `proposed` round can be
recomputed or sent through the normal authorized abort transition. A
`finalizing` round resumes the same FROST session or burns it before a fenced
abort. Recovery never releases an atom because a descriptor or worker is old.

A zero-intent round is not silently treated as settled. After every participant
accepts the output manifest and the governance quorum finalizes it, WS4 emits a
signed `chio.clearing.zero-intent-reconciliation.v1` artifact. Only that typed
   artifact, with fresh lifecycle-transition authority and successful expected-
   head external batch, allows the atom lifecycles to advance without a rail
outcome.

Before the first dispatch, a failed round keeps its atoms unavailable to every
other settlement path until the signed abort/release transition succeeds. After
the first dispatch, they remain reserved until all intents settle or an explicit
compensating reconciliation is authorized; they never return directly to
`per_call`. Operational recovery cannot silently duplicate them.

### Participant authority

The participant snapshot is signed by the configured clearing governance
authority and acknowledged by each included participant. It binds participant
id, accepted identity/key aliases, creditor and debtor roles, settlement
destination, validity window, version, and the accepted v1 netting algorithm.
The snapshot must cover every atom and every output destination. Round-specific
participant signatures are still required before finalization. Unknown aliases,
expired snapshots, conflicting mappings, and a proposer self-signing an
otherwise untrusted mapping reject the round.

### Fail-closed errors

Invalid signature, untrusted participant authority, missing participant
acknowledgement, unresolved or conflicting identity, duplicate atom, incomplete
input range, stale lifecycle or disposition version, reservation conflict,
wrong disposition,
mixed currency, checked-arithmetic failure, conservation failure, output count
or root mismatch, transformation-witness mismatch, missing participant
acceptance, in-window dispute, missing quorum, stale reservation at finalize,
missing or inactive FROST key epoch, roster/transcript mismatch, duplicate
dispatch, unauthorized or post-dispatch abort, malformed zero-intent
reconciliation, and reconciliation/intent mismatch all deny.

## Alternatives considered

1. A new `chio-clearing` crate was rejected for v1. `chio-credit` already owns
   the atom and settlement-exposure contract needed by the pure algorithm.
   Extract only if an actual dependency cycle or independent release boundary
   appears.
2. Direct exposure-ledger plus IOU ingestion was rejected because the two can
   represent one receipt. The shared canonical atom is the only input.
3. Cycle cancellation was rejected as the final algorithm because it cannot
   reduce acyclic chains. Balance computation plus deterministic matching does.
4. Cross-currency v1 was rejected. One round has one currency, with no
   conversion or aggregate mixed total.
5. Mutable packets were rejected. Intent and later observations are separate
   signed artifacts.
6. "Use the proposer participant list" was rejected. Settlement routing needs
   an authoritative mapping before WS4 can run.

## Claim framing

WS4 emits deterministic signed intent over a complete reserved snapshot. It is
not custody, finality, a settlement rail, or consensus over live state.
"Clearinghouse" names the netting function. Settlement truth exists only in
separate WS1 reconciliation evidence, and original atoms remain exclusively
reserved until that evidence is applied.

## Testing strategy

- Deduplication: the same receipt represented by exposure and IOU sources
  produces one upstream atom; duplicate ids and digest aliases reject at WS4.
- Algorithm: reverse bilateral flows cancel; cycles cancel through balances;
  `A -> B -> C` reduces to `A -> C`; shuffled inputs produce byte-identical
  outputs; debtor and creditor totals conserve exactly.
- Arithmetic: every checked overflow and signed-balance conversion failure
  rejects, with no truncated or saturated output.
- Completeness: capped reports, unconsumed cursors, missing positions, wrong
  counts, and omitted manifest leaves reject.
- Reservation races: two rounds contend for one atom and exactly one
  transactional reservation succeeds; per-call and channel observers skip the
  winner.
- Reservation crash recovery: kill after every reservation insert point. A
  committed external reservation always has its complete signed round descriptor,
  retained anchor batch and lifecycle head. Restart repairs from the anchor or
  uses the normal fenced abort, never a restored local row or age-based release.
- Identity: missing, expired, conflicting, or proposer-only mappings reject;
  destinations must match the authoritative snapshot.
- Immutability: changing reconciliation data cannot change an intent; mismatched
  reconciliation rejects.
- Digest graph: core, output leaves, output manifest, acceptances, and
  finalization hash in one direction with no circular dependency.
- Authority and lifecycle: every affected participant accepts the full round;
  no atom is satisfied until all intents settle; after the first dispatch a
  failed intent cannot release originals to `per_call`.
- Quorum: complete participant acceptances without the configured FROST
  aggregate, wrong ladder action class or governance scope, a stale key epoch, or
  a mismatched roster remain non-dispatchable.
- Finalize/abort fence: concurrent finalize and abort attempts yield exactly one
  external batch winner. A stale lifecycle fence or proof cannot dispatch; crash in
  `finalizing` resumes the same FROST session; the first-dispatch/abort race has
  one winner; abort artifact and atom releases roll back together.
- Anti-rollback: restore same-active-epoch SQLite snapshots after anchored
  reservation, finalization, first dispatch, abort and satisfaction. Startup
  repairs to the external round-plus-obligation heads or remains unready; no
  restored round can re-reserve, abort a finalized generation or redispatch.
- Effect slots: restore RFC-0003/payment/round databases before each intent
  dispatch after its external slot commits. The first handoff cannot recur;
  completed/no-effect status binds exact evidence, while unavailable or
  unqualified status remains unknown with obligations reserved. Creating a slot
  without a prior exact `AdmissionOperation::Prepared` rejects. Reconciliation
  and slot terminal state commit in one external batch; round satisfaction
  rejects any live, no-effect-only or unknown intent.
- Zero/abort lifecycle: a typed zero-intent reconciliation requires a finalized
  empty output and fresh lifecycle authority; abort requires proof of zero
  dispatches and stale expected versions reject atom release.
- Lifecycle, schema registry parity, public verifier positives,
  unknown-schema negatives, and workspace gates.

## Implementation phases

1. Prerequisite gate: land the canonical deduplicated
   `chio_credit::obligation::ObligationAtom` producer,
   `chio_credit::obligation::ObligationDisposition` store contract and SQLite
   implementation, complete epoch manifest, and authoritative participant
   snapshot. WS4 stops if any is missing.
2. Land the pure `chio_credit::clearing` single-currency engine and immutable
   artifacts with algorithm, completeness, and verifier tests.
3. Add local staged reservation/lifecycle state, complete replay input, shared
   external economic-state batch integration, anchor-first recovery,
   propose/report/dispute endpoints, and disabled quorum-finalization
   verification. Still no money movement.
4. After FROST Phase 3, authorization-slot continuity and the qualified external
   resource anchor are live, activate finalization only by consuming the exact
   round action in the anchored `finalizing -> finalized` batch. Bind immutable
   intents to separately authorized, effect-slot-fenced WS1 dispatch, and emit
   separate reconciliation artifacts. Prove release/retry without copying an
   obligation. No endorsement-only fallback.
