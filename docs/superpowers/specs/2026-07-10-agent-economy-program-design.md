# Agent Economy Program Design

- Date: 2026-07-10
- Program: agent-economy program (ten workstreams, three waves)
- Normative anchors: `spec/PROTOCOL.md` (5.1-5.2, 6.3.4, 9, 14), `spec/CHIO_LADDER.md` 5.2, `spec/METERING.md`, `docs/reference/AGENT_ECONOMY.md`, `docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`, `docs/architecture/reliability/RFC-0003-dispatch-intent-journal.md`, `docs/architecture/reliability/RFC-0013-money-path-durability.md`, `2026-07-09-protocol-primitives-design.md`, `2026-07-12-admission-operation-design.md`, `2026-07-12-frost-quorum-substrate-design.md`, `2026-07-12-economic-state-continuity-design.md`, `docs/adr/ADR-0006`, `docs/adr/ADR-0015`, `contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json`
- Branch strategy: one branch and PR per independently landable phase, all off
  current `main`; workstream branch names in spec headers are prefixes, and the
  detailed plan owns the exact phase suffix

## Context

Chio's economic layer is three tiers sharing the receipt spine:

1. A kernel-native metered budget path that is production-wired for budgets
   only: capability cost caps, worst-case pre-charge holds, post-execution
   reconciliation, and signed receipts carrying `FinancialReceiptMetadata`.
2. A signed-artifact economic contract layer (13 crates under
   `crates/economy/`) covering listings, open-market bidding with bonds and
   penalties, underwriting, credit and IOUs, liability insurance, bounded
   autonomous pricing, metering, and billing export. It is exercised through
   the CLI and the `chio trust serve` comptroller plane, offline from the
   kernel dispatch path.
3. Web3 runtimes (`chio-anchor`, `chio-link`, `chio-settle`,
   `chio-web3(-bindings)`) with real broadcast code, qualified on local
   devnet only, under a no-mainnet freeze pending external assurance.

The production plug points between tier 1 and everything downstream are
empty: `set_settlement_observer` has no callers, no production
`SettlementHook` implementation exists, `set_payment_adapter` and
`set_price_oracle` are installed only by tests, `CreditEvaluatorHook` has no
production driver, and manifest `ToolPricing` is never read by the charge
path. RFC-0013 catalogs the resulting money-path durability gaps (F68-F74).

This program closes the loop and then builds differentiated market
capability on top of it. Each workstream has its own design spec in this
directory; this document fixes what is shared: the workstream set, the
dependency graph, the sequencing, the invariants every spec obeys, and the
claim discipline.

## Workstreams

| WS | Title | Spec | One-line scope |
|----|-------|------|----------------|
| WS1 | First Light | `2026-07-10-ws1-first-light-design.md` | Production wiring for the money loop plus the RFC-0013 payment participant, canonical obligation/credit admission, and an always-on kernel e2e test over the shared AdmissionOperation |
| WS2 | Chio Paper | `2026-07-10-ws2-chio-paper-design.md` | Direct CAS assignment of canonical obligations with obligor acknowledgement, fresh outstanding evidence, and underwriting-derived discount terms; venue trading is deferred |
| WS3 | Verified-outcome pricing | `2026-07-10-ws3-outcome-pricing-design.md` | Deterministic outcome artifacts; activation waits for a genuine reversible rail, provider durable acceptance, and receiver durable delivery acknowledgement |
| WS4 | Chio Clearinghouse | `2026-07-10-ws4-clearinghouse-design.md` | Deterministic netting over completeness-proven canonical obligations, one fenced round lifecycle, FROST finalization, and separate reconciliation |
| WS5 | Micro-escrow channels | `2026-07-10-ws5-micro-escrow-channels-design.md` | Fully funded devnet channels with pre-dispatch payer reservation, exact token-unit binding, signed cumulative state, and FROST-authorized close |
| WS6 | Agent credit bureau | `2026-07-10-ws6-credit-bureau-design.md` | Issuer-asserted financial credentials with stable source identity, selective presentation binding, complete source proofs, and rollback-pinned lifecycle |
| WS7 | Parametric insurance | `2026-07-10-ws7-parametric-insurance-design.md` | Semantic trigger claims sharing canonical liability coverage, exact payout binding, and opt-in FROST adjudication panels |
| WS8 | Fiscal constitutions | `2026-07-10-ws8-fiscal-constitutions-design.md` | Currency-bound governed economic inputs with required validity and independently anchored activation/clock continuity |
| WS9 | Economic wind tunnel | `2026-07-10-ws9-economic-wind-tunnel-design.md` | Adversarial economic tests and deterministic simulations emitting project-signed internal qualification matrices |
| WS10 | Comptroller Console | `2026-07-10-ws10-comptroller-console-design.md` | Live spend observability: receipt-log cost streaming, budget webhooks, burn-rate projections, spend-anomaly findings feeding underwriting signals |

## Dependency graph and waves

```
Reliability: RFC-0006 base (landed) + serving-owner amendment (pending)
             -> protocol-primitives Task 6 / corrected RFC-0003
             -> WS1 Phase 2 RFC-0013 participant -> WS1 Phase 3

Quorum:      FROST P1 verifier -> P2 durable signing -> P3 runtime qualification
             -> WS1 P4, WS4 P4, WS5 P3, WS7 panel activation

Continuity:  external economic-state contract -> adapter/recovery qualification
             -> WS4 production, WS5 service/close, WS7 payout

Wave 1 (substrate):      WS1 First Light    WS8 Fiscal constitutions    WS10 Comptroller Console

Wave 2 (bounded pilot):  WS3 Outcome artifacts/evaluator   WS2/WS4 artifact contracts
                         WS6 Credit bureau

Wave 3 (advanced rails): WS2/WS4 production  WS5 Channels  WS7 Insurance  WS9 internal qualification
```

Hard edges (blocking):

- RFC-0006's earlier hot-path work is on `main`; its new database-scoped
  serving-owner amendment is owned by protocol-primitives Task 6 and lands with
  it, under `crates/platform/chio-store-sqlite/src/serving_owner/`.
  That task also owns the generic retained
  `AdmissionOperation`, composable receipt projection, top-level/nested dispatch
  parity, and SQLite serving fencing described by corrected RFC-0003. It must
  land before WS1 Phase 2 starts; WS1 does not implement a second coordinator.
  RFC-0013 is a money-path specialization of RFC-0003 and must register its
  payment reconciliation with RFC-0003 recovery; a standalone replacement is
  not an allowed shortcut.
- `spec/CHIO_LADDER.md` requires FROST for `settle.commitment` and every other
  `n_of_m` action. The owned substrate is
  `2026-07-12-frost-quorum-substrate-design.md` and its executable plan:
  `chio/frost-p1-verifier-contract` lands strict domains, roster epochs and
  historical verification; `chio/frost-p2-durable-signing` lands DKG, encrypted
  pre-commit nonce durability, share durability, fenced sessions and the external
  monotonic roster-epoch plus same-epoch authorization-slot checkpoints;
  `chio/frost-p3-runtime-qualification` qualifies P2's rotation and both
  continuity layers across crash, restore and runtime behavior. P3 is a shared
  prerequisite for WS1 P4, WS4 P4 and WS5 P3. WS7 Phase 3 later registers and
  qualifies its reserved action mapping before panel activation. Each consumer
  still owns the rollback-independent resource/effect gate that consumes
  `VerifiedFrostAuthorization` under its exact resource version and fence. A test
  signer, endorsement set, group signature, or rollbackable local CAS does not
  satisfy the gate.
- WS4, WS5 and WS7 irreversible lifecycles depend on the shared external
  multi-resource contract in `2026-07-12-economic-state-continuity-design.md`.
  Its linearizable batch CAS is outside the consumer SQLite restore domain and
  owns the authoritative round/obligation, channel/reservation, and
  trigger/claim/coverage heads. Local rows are staging/cache state. Missing,
  unavailable or divergent continuity keeps the affected dispatcher disabled.
- WS2, WS3, WS4 production money movement depends on WS1 (settlement hook,
  payment adapter wiring, durable journal). Their artifact families and
  offline verification land independently of WS1, in the established
  pure-contract pattern.
- No current in-tree payment adapter qualifies as a genuine reversible rail for
  WS3: `X402PaymentAdapter` is prepaid and both `X402PaymentAdapter` and
  `AcpPaymentAdapter` perform local capture/release bookkeeping. WS3 output-stage
  payment activation is a separate hard edge on a real networked
  hold/capture/release implementation plus idempotency, query, binding, and
  end-to-end qualification. Artifact, eligibility, and pure evaluator work may
  land while that edge remains blocked.
- No current generic in-tree tool server proves provider-owned durable
  acceptance for WS3. Outcome-priced dispatch also requires a provider-signed
  acceptance after restart-safe queueing and a rollback-independent external
  dispatch-slot anchor. Its monotonic checkpoints bind the exact operation,
  attempt, predecessor and version. Only a current permanent external
  cancellation checkpoint proves nonacceptance; a missing local queue row or a
  restored, behind, divergent or unavailable view stays unresolved and freezes
  the hold. Local queue staging is non-executable until external acceptance and
  executor-lease CAS; accepted invocation bytes have rollback-independent
  availability, cancellation permanently fences staged work, and
  accepted/executing/completed attempts cannot cancel. Exact idempotency,
  authenticated tool-side status, external status query, local acceptance-time
  persistence, restore-after-enqueue, restore-after-effect-before-completion and
  the RFC-0003 unresolved-handoff ambiguity gate are mandatory. Socket acceptance
  or in-memory enqueue does not satisfy this hard edge.
- WS3 also requires a receiver-owned durable output store, exact final-byte
  digest and a rollback-independent external delivery-slot anchor. Only its
  current acknowledged checkpoint plus durable blob availability permits a
  signed delivery acknowledgement, and only its current permanent cancelled
  checkpoint permits nonacceptance. Restart, local snapshot restore, external
  status query, anchor outage and wrong-binding qualification are mandatory.
  Provider acceptance proves dispatch handoff, not caller delivery. Capture
  occurs only after the receiver acknowledgement is persisted; ambiguity freezes
  the hold.
- WS3 pre-dispatch eligibility is a participant binding compare-and-swap attached
  before `ReadyToDispatch`. It is persisted with `AdmissionOperation::Prepared`
  and finalized through `AdmissionTerminalProjection::Completed`; a parallel intent actor or
  post-dispatch attachment is not allowed.
- WS2-WS5 production integration also depends on the canonical obligation and
  exclusive-disposition contract in invariant 11. Artifact-only work may not
  invent a parallel ownership, creditor, exposure, or routing model.
- WS4 activation additionally requires an authoritative participant snapshot and
  boundary-complete epoch/range proof before netting; finalization and abort use
  one externally anchored lifecycle CAS. The `finalizing -> finalized` batch is
  the single consumption point for the exact FROST authorization and persists
  its digest. First dispatch consumes the exact anchored finalized tuple plus
  separate fresh WS1 settlement authority; it does not consume the same FROST
  proof a second time.
- WS5 shipped v1 additionally requires fully funded existing `ChioEscrow`,
  block-pinned terms/event/operator proofs, exact protocol-to-token conversion,
  pre-dispatch payer reservation with no post-service payer signature or per-call
  fallback, guarded prepare/root publication/broadcast and event-bound
  reconciliation. Artifacts with close disabled are incomplete v1.
- WS7 payout execution depends on WS4 or WS1 dispatch; its trigger and
  evidence machinery depends on WS3 (SLA breach events) only for the
  SLA-trigger class. Any payout activation also depends on its deterministic
  claim/contest state, semantic trigger uniqueness, exact beneficiary/destination
  binding, and shared canonical liability-coverage reservation store.
- WS6's settlement-reliability credential depends on WS1 obligation and
  reconciliation stores exposing authenticated, boundary-complete ranges at one
  cutoff. Other WS6 credential families may land without that metric; a bounded
  source bundle cannot substitute for denominator completeness.
- WS5 on-chain close depends on WS1 and on contract-freeze posture; any new
  contract surface is a family-v2 proposal gated on external assurance and
  is out of scope for the shipped wave.
- WS6 and WS10 coordinate one strict underwriting policy-input version before
  either new signal arm ships. This is a schema edge, not an implied data-flow
  edge. WS6 cross-issuer activation also requires stable source-passport identity
  and a rollback-independent lifecycle high-water pin.
- WS8 activation requires an independently durable fiscal continuity anchor and
  rollback-resistant clock. A local SQLite marker is not bootstrap proof.
- WS10 may ship read-only spend analytics without underwriting activation, but
  signed anomaly/decision policies and current decision heads require its
  external underwriting-governance anchor. SQLite-only lifecycle heads cannot
  admit signals or persisted decisions.
- WS9 attacks the markets, so its ordinary regression scenarios follow the
  owning validators. A shared runner waits until Wave 2 interfaces stabilize
  and shared campaign code proves a distinct boundary. Wave 3 entry requires the
  separately owned `AE-CREDIT-ADMISSION-1` and
  `AE-CUMULATIVE-APPROVAL-1` operation-owned production controls and their
  concurrency gates; WS9 only reruns them.

Soft edges (compounding, not blocking):

- None are active in v1. WS8 parameter adoption, WS10-to-WS6 credential input,
  and WS6-to-WS2 pricing were considered but are not declared by the downstream
  contracts. A later phase may add one only with an exact versioned input,
  authority resolver, evidence-class floor, activation order, and fail-closed
  fallback; this program does not imply those bindings.

## Shared invariants (design law for every workstream)

1. Authority and evidence. Before dispatch, capability validation and the
   applicable policy and guard decisions authorize or deny the proposed
   action. A receipt is the signed post-action record of the mediation
   decision and observed outcome; it is evidence, not the authority that
   permitted the action. Every new artifact is evidence-referential and
   digest-bound to receipts or other signed artifacts, and any later economic
   action must carry its own valid pre-action authority. Payment-rail, chain,
   PSP, and issuer-authored payloads remain subordinate digest-bound evidence.
   No artifact upgrades asserted provenance to observed or verified; evidence
   classes are preserved end to end.
2. Money representation. Every protocol-denominated monetary commitment is
   `chio_core_types::capability::scope::MonetaryAmount` (u64 minor units,
   ISO-4217). A rail-native token or ledger amount may also carry typed base
   units only when an immutable asset-binding digest pins chain, contract/asset,
   decimals and conversion rule; checked conversion must round-trip exactly to
   the bound `MonetaryAmount`. Both representations enter signatures, resource
   fences and reconciliation when both exist. Shares and margins are integer
   basis points. Exchange rates
   are integer rationals with signed `OracleConversionEvidence`. No floats
   in money math; floats stay confined to risk coefficients. Arithmetic that
   creates or changes a monetary commitment is checked and fails closed on
   overflow; it never wraps or silently turns overflow into a payable cap.
3. Fail-closed. Verification errors deny. Invalid artifacts and policies
   reject at load time. Mixed-currency aggregation yields null totals unless
   conversion evidence is attached. Missing pre-action authority or required
   post-action receipt evidence rejects.
4. Boundary discipline. Reuse an existing owning crate first. A new crate is
   justified only by a distinct ownership and dependency boundary, not merely
   by a new artifact family. Pure contract code (`#![forbid(unsafe_code)]`,
   serde types, deterministic validation) performs no filesystem, clock, or
   network I/O. Persistence goes behind traits implemented in
   `platform/chio-store-sqlite`. Chain broadcast and chain RPC live only in
   web3-feature-gated runtime crates. HTTP webhook, oracle, PSP, and rail I/O
   lives in runtime or adapter crates and must use the typed
   `HttpEgressContract` with exact-authority validation, redirects denied, and
   bounded responses. Kernel integration goes through existing hook slots and
   `chio-control-plane` wiring, never through new kernel-side business logic.
5. Schema and verifier discipline. Artifacts are canonical JSON (RFC 8785),
   signed, with versioned schema identifiers
   (`chio.<family>.<artifact>.v1`) declared as constants, JSON schemas under
   `spec/schemas/`, and conformance coverage. Every signed family must land in
   the runtime and CLI registries together, with a registry-parity test,
   unknown-family/schema/version negatives, and signed positive plus tampered
   verifier fixtures. Wire-visible changes reconcile with `spec/PROTOCOL.md`
   in the same phase. No public claim advances until the claim registry,
   release-truth checks, and verifier-backed fixtures all agree.
6. Freeze discipline. No mainnet or public-testnet deployment, production
   custody claim, or promotion. The existing devnet `ChioEscrow` and
   `ChioBondVault` do hold test assets and have transferable admins, token
   allowlists, and pause controls. A pause blocks release/impairment but not the
   eventual refund/expiry path, so it is an admitted liveness and outcome trust
   assumption, not a non-discretionary guarantee. This program neither adds nor
   widens a privileged or upgrade lane. Forced closures never re-price and never
   pay the protocol. ADR-0015 records the live limitation; any new on-chain need
   or admin-model change is a family-v2 proposal gated on external assurance.
   Shipped scope is devnet qualification only.
7. Bounded-profile honesty. Nothing in this program claims
   distributed-linearizable budget or spend truth. The HA overrun bound
   (ADR-0006) stands. Netting, channels, and settlement surfaces are signed
   intent plus reconciliation evidence, not custody and not finality claims
   beyond the documented independent-head checks.
8. Ladder anchoring. Financial action classes bind to `spec/CHIO_LADDER.md`
   5.2: facility binding and liability auto-bind stay bilateral-required;
   settlement commitments stay n-of-m quorum-required. New action classes
   introduced by a workstream are added to the ladder with an explicit
   governance mode in the same phase. No `n_of_m` action activates until the
   production FROST verifier and trusted roster/group-key epoch prerequisite in
   the hard edges is satisfied.
9. House rules. No em dashes anywhere. No process-narration comments.
   Conventional commits. Clippy `unwrap_used`/`expect_used` deny. The
   workspace gate (`cargo build --workspace && cargo test --workspace && cargo
   clippy --workspace -- -D warnings && cargo fmt --all -- --check`) passes
   before any phase is declared done.
10. Roadmap framing. Every workstream states its claim track (release gate,
    implementation, external evidence) and never widens a public claim
    implicitly. Live capital remains a separate product track.
11. Canonical obligations. `chio_credit::obligation` is the sole type owner for
    `ObligationAtom`, `ObligationDisposition`, the authenticated transition
    event, and the backend-neutral store trait; `chio-store-sqlite` owns the
    durable implementation. Before WS2-WS5 production integration, the
    immutable atom must bind a stable `obligation_id`, debtor,
    `original_creditor`, amount,
    currency, due/expiry terms, pre-action authority digest, and source receipt
    digest. A receipt, IOU, exposure entry, assignment, channel update, or
    clearing packet may reference that obligation but may not mint a second
    economic claim for the same value. Each live obligation has exactly one
    durable disposition: `per_call`, `assigned`, `channelized`, or
    `clearing_reserved`. For an operation-covered request, RFC-0003's
    `commit_admission_projection` transaction appends the receipt, compare-and-
    swaps the exact retained operation to `Completed`, and commits all applicable
    local projections. `DurableAdmissionMode::All` may also cover read-only
    requests. Whenever a paired observer is installed it seeds
    durable attempt-zero work for every receipt; for positive outstanding value
    it additionally
    commits the immutable atom, initial disposition, and creation event. All
    applicable receipt-side rows commit atomically before any observer or
    downstream settlement path runs. Any failure leaves every projection absent
    and the retained operation nonterminal for recovery. Cross-database payment
    remains an idempotent saga participant. Disposition changes
    append an authenticated audit event
    and update the current projection by compare-and-swap in one transaction;
    the current creditor resolves only from that disposition (`per_call` uses
    `original_creditor`; `assigned` names the acknowledged assignee); no mutable
    owner field exists on the atom. Aggregators reject duplicates and never sum
    a summary envelope alongside its source obligations. Settlement lifecycle
    remains a separate state dimension. Missing original or current creditor
    identity, fresh outstanding evidence, or exclusive disposition rejects fail
    closed.
12. Durable admission. Exactly one fenced `AdmissionOperation` keyed by immutable
    request identity coordinates budget, payment, approval, nonce, provider,
    receipt, observer and obligation participants. `Prepared` precedes the first
    authoritative mutation; every required late evidence binding attaches by
    one-time CAS before `ReadyToDispatch`; `DispatchCommitted` precedes top-level
    and nested tool handoff. Terminal operations remain replay tombstones. After
    dispatch commitment, recovery never blindly redispatches or releases a hold
    without authenticated no-effect or zero-charge proof. SQLite mutable serving
    has one exclusive owner epoch.
13. Quorum authorization. All `n_of_m` execution uses the shared strict
    `FrostAuthorizationV1` verifier, durable signer sessions, active roster/group
    epoch and same-epoch authorization slot reconciled to external monotonic
    checkpoints, and the exhaustive exact domain/action registry.
    A group signature proves threshold-group
    authorization, not the signer subset. The external slot prevents a second
    conflicting message for one resource version/fence. The consumer consumes
    `VerifiedFrostAuthorization` through its rollback-independent current-resource
    gate; a rollbackable local CAS alone cannot begin an effect. Registered
    classes without that owned gate remain disabled.
14. Anti-rollback state. A claim that bootstrap is permanently closed, a clock
    only advances, or a lifecycle cannot regress requires an authenticated
    monotonic anchor outside the protected SQLite backup/restore domain. Local
    high-water rows are caches. Missing, unavailable, behind, ahead or divergent anchor
    state fails closed before serving the affected authority. WS4 round plus
    obligation heads, WS5 channel plus reservation heads, and WS7 trigger/claim
    plus shared coverage heads advance through bounded external multi-key batches
    before capacity, release, or dispatch becomes eligible. Every protected
    external handoff also consumes a permanent operation-bound effect slot after
    the matching `AdmissionOperation` handoff state commits. Recovery after that
    slot can only query authenticated target status or use separately qualified
    same-key idempotency; otherwise it stays unknown and locked without replay.

## Claim and release framing

- Release gates. WS1 completes the RFC-0013 payment participant over the shared
  durable admission substrate; "the
  production money loop is closed" becomes claimable only when the RFC-0013
  target invariant (moved funds imply an attested receipt or a
  reconciliation incident) is enforced by an always-on kernel e2e test and
  the F68-F74 findings are closed. The contract freeze and its
  external-assurance gate are untouched by this program.
- Implementation. WS1-WS8 and WS10 are engineering within the bounded
  release posture. WS4 must not describe netting output as settlement truth;
  it emits signed net-position statements and immutable settlement intents that the
  existing quorum-gated settlement surface consumes.
- External evidence. WS9 initially produces project-signed internal
  qualification results. Those signatures authenticate the signer and bind its
  declared inputs and result; deterministic replay is established only by an
  independent rerun. They do not prove robustness, underwriting facts, or
  insurability. A WS9 result becomes external evidence only after an independent
  runner or witness signs a provenance-complete corpus and run, with the claim
  scope named explicitly. WS6 home-authority reports are
  authenticated issuer assertions; receivers preserve them as
  imported/asserted evidence unless independently corroborated. Cross-issuer
  exchange requires a partner pilot before any cross-org trust claim.
  Comptroller market-position thresholds remain unproved and are not advanced
  by this program.

## Program-level risks

- Scope gravity. Ten workstreams invite parallel sprawl. Mitigation: waves
  are strict; a wave-2 workstream may land artifact contracts early but may not
  wire production money movement before WS1 phases complete.
- Freeze collision. WS5 is the workstream most likely to want contract changes.
  Mitigation: v1 is designed against an already funded `ChioEscrow`; anything
  requiring new Solidity is explicitly deferred to a family-v2 proposal
  document. WS3 lands artifact and evaluator contracts only until both a real
  typed reversible rail, provider-authenticated transport with external
  rollback-independent attempt continuity, and receiver-authenticated delivery
  with external rollback-independent slot and blob continuity are implemented
  and qualified.
- Claim drift. Insurance, credit, and clearing vocabulary reads as regulated
  activity. Mitigation: every spec carries the "signed intent and evidence,
  not custody, not insurer-of-record, not a rail" boundary language, and
  reuses the disclaimers already normative in `spec/PROTOCOL.md` 9 and 14.
- Parameter authority split. WS8 moves constants into governed artifacts;
  consumers may use built-in values only before the first activation. After
  activation, a missing, invalid, expired, or rolled-back artifact retains the
  last-known-good schedule or denies; it never restores looser defaults. The
  external fiscal anchor, not a restored SQLite marker, proves this continuity.
- Reliability-program coupling. RFC-0006 base work is on `main`, while its
  serving-owner amendment and RFC-0003 are hard
  prerequisite for WS1 Phase 2. RFC-0013's boot reconcile registers into
  RFC-0003's boot-recovery orchestration. No standalone reconcile substitute
  may satisfy the phase entry gate.
- Quorum substrate. Ladder policy requires FROST for settlement commitments.
  P1 verification may proceed in parallel, but P2 mutable signer/coordinator and
  roster stores wait for protocol-primitives Task 6's shared database-UUID
  serving-owner fence and reuse it without a second lock.
  The release claim and every quorum action remain disabled until owned P1-P3
  work, external authorization slot and consumer rollback-independent
  resource/effect gate are qualified; documentation, fixtures, local-only CAS, or
  independent participant endorsements cannot be treated as an implementation.
- Qualification laundering. Project-generated synthetic corpora can be useful
  regressions but are not independent evidence. WS9 begins as ordinary tests
  and internal qualification, and no wave exits with an unresolved Critical or
  High finding in its scope.

## Process

Each workstream spec in this directory carries: grounded context,
in/out-of-scope cuts, artifact and type design, integration points,
alternatives considered with a recommendation, claim framing, testing
strategy, and milestone-level implementation phases. The program roadmap and
the detailed executable plan for Wave 1 live under `docs/superpowers/plans/`.
Detailed per-task plans for Waves 2 and 3 are written per-wave at execution
time, after the preceding wave's phase gates pass, following
`superpowers:writing-plans`.
