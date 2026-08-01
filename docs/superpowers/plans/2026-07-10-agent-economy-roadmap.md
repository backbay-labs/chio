# Agent Economy Program Roadmap

> **For agentic workers:** This is the program coordination plan, not an
> executable task plan. Detailed per-phase plans live beside it (see the
> plan index below) and follow superpowers:writing-plans; execute those with
> superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Sequence the ten agent-economy workstreams (WS1-WS10, specs under
`docs/superpowers/specs/2026-07-10-*`) so the production money loop closes
first, market capability lands on top of it, and every claim stays inside
the bounded release posture.

**Source specs:** `2026-07-10-agent-economy-program-design.md`, the ten WS specs
it indexes, and the shared FROST and economic-state continuity designs.

## Global Constraints (inherited by every per-phase plan)

- Workspace gate before any phase is declared done: `cargo build --workspace
  && cargo test --workspace && cargo clippy --workspace -- -D warnings &&
  cargo fmt --all -- --check`.
- No `.unwrap()` / `.expect()` in new code including tests (workspace lints
  deny them). No em dashes anywhere. Conventional commits.
- Every protocol-denominated commitment is `MonetaryAmount` (u64 minor units,
  ISO-4217). Rail-native base units require an immutable asset/decimals binding,
  checked exact conversion and round-trip proof; both representations are signed
  and reconciled. Shares and margins are integer basis points, while discounts
  retain their owning consumer's declared unit; commitment arithmetic is checked
  and fails closed on overflow.
- Fail-closed everywhere. Capabilities plus policy and guard decisions are
  pre-action authority; receipts are signed post-action evidence. Evidence
  classes never silently upgrade (program invariants 1-3).
- No mainnet or public-testnet deployment, production custody claim, or new
  Solidity. Existing devnet escrow/vault admin, token-allowlist, and pause trust
  assumptions remain explicit; this program adds no privileged lane. On-chain
  changes are family-v2 proposals gated on external assurance (program invariant
  6 and corrected ADR-0015).
- Pure contract code performs no I/O. Chain I/O is web3-feature-gated; HTTP
  webhook, oracle, PSP, and rail I/O uses the typed `HttpEgressContract`.
- New crates require an ownership and dependency boundary. Reuse an existing
  owning crate when it already fits.
- Every signed family exits a phase only with runtime/CLI registry parity,
  unknown-family/schema/version negatives, signed positive and tampered
  verifier fixtures, and reconciled claim/release-truth gates.
- No wave exits with an unresolved Critical or High finding in its scope.
- No `n_of_m` action activates before the owned FROST P1 verifier, P2 durable
  signer, and P3 runtime qualification branches land with trusted active roster,
  group key, externally anchored key epoch and authorization slot, exhaustive
  domain/action mapping, and rollback-safe rotation. Each consumer must also
  consume the verified authorization through a rollback-independent current
  resource/effect gate. Test signers, independent endorsements and a local-only
  resource CAS do not satisfy this gate.
- WS4, WS5 and WS7 protected lifecycles require the shared external
  `EconomicStateAnchor` batch contract and restore qualification. SQLite is only
  staging/cache state; no protected capacity, release or dispatch may run while
  its external resource heads are missing, unavailable or unreconciled. Each
  protected target call additionally requires the one-time external
  operation-bound effect-slot CAS after the matching `AdmissionOperation`
  handoff state; a readable current head is not reusable dispatch authority.
- Exactly one retained `AdmissionOperation` coordinates every configured
  monetary or side-effecting call. Protocol-primitives Task 6 owns its store,
  receipt projection, nested/top-level parity and SQLite serving fence. No
  workstream creates a parallel dispatch journal.
- One branch and PR per independently landable phase; exact branch names live in
  each detailed plan.

## Tracks

Per the release discipline, work is separated into three tracks; mixing them
hides the dependencies that govern release.

### Track A: release gates

- RFC-0006 base hot-path work is on `main`; its database-scoped serving-owner
  amendment lands in this program, under
  `crates/platform/chio-store-sqlite/src/serving_owner/` (path identity, lease
  history, global commit chain and rollback anchor). Protocol-primitives Task 6
  owns that amendment and corrected RFC-0003, and corrected RFC-0003 must
  land before WS1 Phase 2. Its retained operation, composable receipt projection,
  shared dispatch boundary, serving fence and boot recovery are not replaceable
  by a standalone payment reconciler.
- RFC-0013 payment participant (inside WS1 phases 2-4): the claim "the
  production money loop is closed" is assertable only when the always-on
  end-to-end test enforces the RFC-0013 target invariant and F68-F74 are
  closed. Qualification soaks cumulative `Off -> Monetary -> SideEffecting`,
  then releases with compiled production default `SideEffecting`; `All` remains
  opt-in and `Off` unsafe-dev only. Because the ladder class
  `settle.commitment` is `n_of_m`, that claim is also blocked until the global
  production FROST prerequisite is met and exercised by the end-to-end test.
- FROST follows `chio/frost-p1-verifier-contract` ->
  `chio/frost-p2-durable-signing` ->
  `chio/frost-p3-runtime-qualification` under the 2026-07-12 executable plan.
  P1 may run in parallel with the serving-owner work; P2 starts only after
  protocol-primitives Task 6's database-UUID `open_serving` fence lands and reuses
  it for every mutable FROST store.
  P3 joins WS1 P4, WS4 P4 and WS5 P3; each join includes the consumer's exact
  rollback-independent resource/effect gate. WS7 Phase 3 later registers and
  qualifies its reserved action mapping before panel activation.
- The web3 contract freeze and its external-assurance checklist are
  untouched by this program and continue to gate any on-chain promotion.

### Track B: implementation

- Wave 1 (substrate): WS1 closes real fail-closed defects, then builds the
  RFC-0013 journal on landed RFC-0003; WS8 resolves governed parameters; WS10
  ships the indexed read-only spend stream first. The shared economic-state
  contract/adapter may begin in parallel; its SQLite cache waits for the serving
  owner amendment.
- Wave 2 (bounded market pilot): define and verify the canonical obligation
  and exclusive-disposition contract before any WS2-WS5 production
  integration. Pilot WS3 artifacts, pre-dispatch eligibility binding, and the
  pure `ZeroCharge` evaluator with a small deterministic predicate vocabulary.
  No current in-tree adapter qualifies for `HoldCapture`, so payment activation
  remains blocked on a real reversible rail and its qualification. No current
  generic tool server proves provider-owned durable acceptance either, so the
  output-priced path also waits for the signed, restart-queryable acceptance
  transport and zero unresolved-handoff gate. WS6 ships
  issuer-authenticated, imported/asserted credentials. WS2 and WS4 stay
  artifact-only until their ownership and deduplication gates pass.
- Wave 3 (advanced rails): production WS2 and WS4 integration, WS5 channels,
  and WS7 insurance start only after their named evidence and exclusivity
  gates pass. WS9 begins as ordinary regression tests and internal
  qualification.

### Track C: external evidence

- Project-signed WS9 matrices are internal qualification. They become citable
  external evidence only when an independent runner or witness signs a
  provenance-complete corpus and run for the stated claim scope.
- WS6 cross-issuer credential exchange requires a partner pilot before any
  cross-org trust claim. A home authority's signature authenticates its own
  report but does not turn that report into objective or independently
  verified truth; receivers preserve its imported/asserted evidence class.
- Comptroller market-position thresholds remain unproved; nothing in this
  program advances that claim.

## Wave schedule and exit gates

### Wave 1

Entry: specs approved on this branch; RFC-0006 base work confirmed on `main`.
Execute its pending serving-owner amendment with
protocol-primitives Task 6 / corrected RFC-0003, FROST P1 and economic-continuity
Tasks 1-2 as parallel foundation lanes. WS1 Phase 2, FROST P2 and
economic-continuity Task 3 wait for the serving-owner amendment; FROST P3 follows
P2.

- WS1 phases: 1 only real fail-closed behavior (F68 routing consumer and F72
  currency-mismatch deny); 2 RFC-0013 payment participant and sweeper (F70, F71,
  F73, F74) behind `Monetary` qualification, starting only after the generic
  operation substrate
  lands; 3 the configuration fields and `configure_*` functions together with
  the production settlement hook, async settlement runtime, credit IOU
  driver, `AE-CREDIT-ADMISSION-1`, canonical obligation store, adapter, and oracle
  they actually install (F69); 4 always-on end-to-end proof through FROST P3 and
  release under fixed `SideEffecting` default after soak. No Phase 1 no-op
  configuration seam is an exit artifact.
- WS8 phases: 1 artifact family, fixed-point money math, schemas, and parity; 2
  currency-bound tier limits, required expiries, amendment lifecycle, fiscal
  continuity checkpoint/anchor contract and pure resolver; 3 staged persistence,
  independent anchor adapter and startup recovery plus non-activating
  propose/admit/approve/preview commands; 4 all five consumer adapters, both
  open-market issuance gates, an atomic readiness record, then staged-local,
  anchor-CAS, local-finalize activation and rotation plus ladder class
  `fiscal.amendment_activate`. No Phase 3 command may set `ever_activated`, and
  an anchor-unavailable or restored-old database never serves fallback.
- WS10 phases: 1 pure contracts and schemas; 2 a full-`u64` order-preserving
  derived cost key, authenticated tenant sequence/time projections, index, and
  currency-bound read-only spend event stream; current-schema opens use a
  fixed-size schema/index/guard manifest, full row reconciliation is limited to
  migration and explicit audit, and page/count share one reader snapshot; 3
  exact-window burn-rate/anomaly reports, signed
  anomaly/decision-policy lifecycle, external governance anchor, coordinated
  policy-input-v2 and strict underwriting decision-v2 chain; 4 tenant-admin,
  ordered, leased durable
  threshold webhooks. The cost index belongs to WS10 Phase 2 and is not deferred
  to WS1.

Exit gate: WS1 Phase 4 green (release-gate claim assertable), including the
  canonical obligation, credit-admission and exclusive-disposition contract from
  Phase 3, with one `commit_admission_projection` transaction appending the
  receipt, retaining the completed operation, and committing applicable
  obligation sidecars and attempt-zero observer work before
observers; WS1 Phase 3 settlement-reliability due-time/obligation indexes,
signed same-cutoff checkpoints, range/boundary/absence proofs, and restart/tamper
negatives green; WS8
  Phase 4 resolver live through all five adapters with fail-closed
  last-known-good tests and the activation-before-readiness negative green;
WS8 Phase 4 additionally passes old-snapshot restore, anchor-outage and every
two-phase crash point; WS10 indexed read-only stream green. Webhooks and detector-to-underwriting
wiring may follow without blocking the substrate exit.

### Wave 2

Entry: Wave 1 exit gate. In particular, the canonical
`chio_credit::obligation` contract and `chio-store-sqlite` implementation from
WS1 Phase 3 must already satisfy program invariant 11: original/current creditor and debtor
binding, stable identity, source authority and receipt digests, duplicate
rejection, and authenticated compare-and-swap transitions among exactly one of
`per_call`, `assigned`, `channelized`, or `clearing_reserved`. WS2-WS5 may do
design work before this gate, but no production integration or independently
invented obligation type may land.

- WS3: a bounded `chio_listing::outcome` artifact/evaluator pilot with
  a typed `VerifiedOutcomeRequestV1` metered-billing extension,
  `chio.outcome.eligibility.v1`, a small deterministic JSON Pointer vocabulary,
  verdict metadata, and kernel predicate evaluation. The eligibility record and
  its digest attach to `AdmissionOperation::Prepared` before dispatch and
  finalize through `AdmissionTerminalProjection::Completed`. Capture/release
  activation is not a Wave 2 exit artifact: `X402PaymentAdapter` is prepaid and
  `X402PaymentAdapter`/`AcpPaymentAdapter` capture/release is local bookkeeping.
  A real reversible rail must be implemented and pass idempotency, query,
  binding, release, anchored-time capture-deadline, permanent post-ack recovery,
  and end-to-end qualification before the output-stage payment hook can activate.
  The provider path reuses the generic `ProviderAttemptCheckpointV1` family and
  qualified `DispatchStatusProvider` verifier; WS3 adds no duplicate dispatch
  checkpoint family. The path must independently pass durable enqueue, signed
  acceptance, rollback-independent monotonic attempt continuity, external
  status-query, acceptance-time index, lost-ack, non-executable local staging,
  invocation-blob availability, external executor lease/fencing,
  restore-after-enqueue and restore-after-effect-before-completion
  qualification. Only generic `VerifiedProviderNotAccepted` over a current
  permanent external cancellation checkpoint proves nonacceptance; local queue
  absence or a restored, behind, divergent or unavailable view freezes the
  hold. Cancellation makes staged work permanently non-executable; an accepted,
  executing or completed attempt can never cancel. Recovery may finish an
  executing attempt only from authenticated tool-side status or qualified
  same-key idempotent invocation.
  A third independent receiver path must persist the exact final bytes in a
  rollback-independent blob store before exposure and advance an external
  monotonic delivery slot before signing the acknowledgement. It must pass local
  snapshot restore, external status-query, anchor-outage and wrong
  operation/output/receiver binding qualification.
  Capture happens only after that durable acknowledgement and only for `Passed`;
  acknowledged `Failed` or deterministic `Unevaluable`, verified cancellation,
  and durable pre-delivery contractual zero all release. Acknowledgement validity
  is checked against its anchored accepted time and remains permanent afterward.
  Missing or ambiguous acknowledgement enters recoverable `delivery_unknown`,
  freezes the hold and emits no receipt; only a current anchored acknowledgement
  or permanent cancellation resolves it. None of the three gates substitutes
  for another.
- WS2: direct `chio_credit::factor` CAS assignment; discount pricing over
  underwriting inputs; obligor acknowledgement; ladder class
  `factor.assignment_bind`. Venue and penalty integration are deferred.
  Production assignment waits for payee-bound source receipts, fresh outstanding
  evidence, and shared non-equivocation.
- WS4: `chio_credit::clearing` engine and artifacts; round orchestration endpoints;
  reconciliation binding through WS1 surfaces; ladder class
  `clearing.round_finalize`. Its inputs are an authoritative participant snapshot
  with boundary-complete epoch/range proof over canonical obligations, not IOU or
  exposure summaries counted beside their source rows. Finalize and abort share
  one external lifecycle head. Finalization remains disabled in this wave and
  until FROST P3 plus the exact anchored round/obligation batch is qualified.
- WS6: `chio.fincred.*` credential family with stable credential IDs, signed
  source manifest, exact selective-presentation digest, complete aggregate-source
  proofs and rollback-pinned lifecycle; verifier policy and coordinated strict
  underwriting input version that preserves home-issued
  facts as imported/asserted unless independently corroborated. Reliability VC
  issuance is gated on a fresh verified WS1 Phase 3 checkpoint/range proof; no
  bounded bundle or table scan satisfies the gate.

Exit gate: canonical obligation invariants proven under duplicate and
concurrent-transition negatives; all four artifact families satisfy the
registry, unknown-schema, verifier-fixture, PROTOCOL, CHIO_LADDER, and claim
gates; every production money movement path routes through WS1 surfaces; no
Critical or High finding remains unresolved.

### Wave 3

Entry: Wave 2 exit gate plus both production controls: WS1 Phase 3
`CreditAdmissionStore::reserve_exposure` with its operation-owned exposure CAS,
and protocol-primitives `AE-CUMULATIVE-APPROVAL-1` in the composite budget hold.
Their race, restart and nested/top-level parity suites are green before any Wave
3 activation work starts. Economic-continuity Tasks 1-4 and a
production-qualified external adapter are also green; each WS4/WS5/WS7 path still
must pass its consumer batch matrix in Task 5.

- WS2: activate assignment and factoring over canonical obligations only after
  creditor binding, fresh outstanding evidence, and shared non-equivocation
  pass; route settlement through WS1 and preserve exclusive `assigned`
  disposition until resolution.
- WS4: activate clearing rounds over obligations atomically reserved in the
  `clearing_reserved` disposition only after snapshot completeness and FROST P3;
  consume `chio.frost.clearing-round-finalize.v1` once in the externally anchored
  `finalizing -> finalized` round-plus-obligation batch. First dispatch requires
  that exact finalized head plus separate fresh WS1 settlement authority. Enforce
  immutable settlement intents with separate reconciliation
  and reject any summary artifact
  counted beside its source obligations.
- WS5: ship v1 only as a fully funded state machine over existing `ChioEscrow`:
  block-pinned terms/event/operator proof, exact protocol amount to token-base-
  unit round trip, pre-dispatch irrevocable payer reservation with no post-service
  payer signature or per-call fallback, exclusive channel disposition, guarded
  prepare/root publication/broadcast, event-bound reconciliation, and close/
  dispute watchdogs. Quorum close consumes FROST P3 authorization under the exact
  externally anchored channel/escrow-reservation state version/fence; every
  service reservation is externally anchored before tool dispatch;
  family-v2 proposal document for atomic on-chain close (proposal only).
- WS7: `chio.parametric.*` policy and trigger evaluation; auto-claim assembly;
  semantic trigger identity over stable source/index/subject/window/sequence/
  count/selected-root fields, atomic contest lifecycle, canonical insured-subject
  beneficiary binding in v1, and shared canonical liability-coverage reservation
  across legacy and parametric claims. Reuse `EconomicStateBatchV1`, shared
  resource heads, and the existing effect slot for unique payout intent and
  reconciliation binding; no WS7-private continuity coordinator or parallel
  authoritative projection is allowed. Single-adjudicator artifacts may land
  before FROST, but production claim processing and payout dispatch remain
  disabled until the legacy claim path uses the same ledger and head API, and
  n-of-m adjudication-panel supersession and settlement dispatch remain disabled
  until their production quorum prerequisites pass.
- WS9: implement the six scenario classes as ordinary tests first. A thin
  deterministic runner may later emit project-signed internal qualification
  matrices; the advisory `ci-gates/` facet cannot launder them into external
  evidence. Both named controls are already entry gates. WS9 owns only their
  diagnostic reruns, not those production validators.

Exit gate: WS2 assignment and WS4 clearing production paths preserve exclusive
obligation disposition and reconcile through WS1, with WS4 finalization proven
  through FROST P3 plus its round lifecycle CAS; channels ship the complete
  devnet-funded off-chain
state machine over the existing qualified escrow, with quorum close enabled
  only through that verifier and channel CAS; the parametric tier is live against
  completeness-proven replayed corpora with semantic claim/contest CAS and
  legacy-plus-parametric coverage non-equivocation, with the legacy path live on
  that same ledger before production parametric claim processing or payout
  dispatch, while panel supersession is optional and remains disabled without
  FROST P3 and its claim CAS; both named
  admission controls remain live and their WS9 scenarios run rather than report
  `NotRun`;
  WS9 tests are green with no unresolved Critical or High finding. Scheduled
  project-signed matrices are
optional internal artifacts, not an exit substitute.

## Cross-program checkpoints

- RFC-0003 boot recovery: RFC-0013 registers its boot reconcile into
  RFC-0003's orchestration. RFC-0006 base is on `main`, but its serving-owner
  amendment is not; protocol-primitives Task 6 owns and must land that amendment,
  the retained operation, projection and path parity before WS1 Phase 2. No
  standalone boot-reconcile entry point or
  WS1-local coordinator may waive or replace that dependency.
- FROST executes through the written 2026-07-12 P1-P3 plan. Shared P3 is
  necessary but not sufficient: WS1, WS4, WS5 and WS7 each qualify their own
  exact action domain and resource version/fence CAS.
- Reliability plans already under `docs/superpowers/plans/` (rfc-0002,
  rfc-0006, rfc-0007, rfc-0011) share kernel surfaces with WS1; rebase WS1
  phase branches over their merges rather than the reverse.

## Program decision log (from spec open questions)

- Authority/evidence: capabilities plus policy and guards authorize before
  action; receipts attest the decision and outcome afterward. Later economic
  actions require fresh authority.
- Obligation routing: WS2-WS5 share one canonical obligation identity and one
  exclusive durable disposition. Summary artifacts never count beside their
  source obligations.
- Boundaries: pure crates do no I/O; chain I/O is web3-feature-gated; HTTP
  egress uses `HttpEgressContract`; new crates require a real ownership and
  dependency boundary.
- WS2: ship fraud penalties on the existing `FraudulentListing` abuse class
  first; the dedicated `FraudulentAssignment` variant lands as a coordinated
  open-market revision in the same wave.
- WS3 guard integration: durable admission finalization now freezes and runs the
  existing post-invocation guard pipeline. WS3 must extend that same durable
  post-return record with outcome evaluation after the final guard mutation and
  before delivery. Durable block/escalation mapping to contractual zero remains
  implementation work; a second guard pipeline or bypass is forbidden.
- WS3 rail and dispatch gates: artifacts, eligibility binding, and the pure
  evaluator may land first. No production outcome-priced payment path activates
  until a real reversible rail with anchored-time capture-deadline and permanent
  post-ack recovery, provider-authenticated durable acceptance backed by the
  generic external rollback-independent attempt continuity, and
  receiver-authenticated durable delivery backed by external
  rollback-independent slot and blob continuity each pass their WS3
  crash/restore and ambiguity qualification matrices; no current in-tree adapter
  or generic tool server supplies all three.
- WS4: clearing uses the sibling `chio.clearing.settlement-intent.v1` family.
  The existing commerce settlement packet is order/merchant/PSP-specific and
  carries mutable reconciliation fields, so it is not extended. PROTOCOL 6.3.4
  records the sibling intent plus separate reconciliation families in Phase 1.
- FROST: P1 owns strict verifier/domain/roster contracts, P2 owns durable nonce,
  share, session fencing, DKG, rotation and external monotonic epoch plus
  authorization-slot checkpoints, and P3 owns crash, same-epoch restore, rotation,
  exhaustive registered-action mapping and runtime qualification. WS7 adds its
  reserved action mapping in Phase 3. Consumer rollback-independent resource
  gating remains in each workstream. No workstream silently implements or mocks
  that prerequisite.
- WS7: rate-trigger corpus completeness needs an anchor-epoch attestation;
  design lands with the trigger evaluation phase, not after. Evidence identity
  retains stable source/index/subject/window/sequence/count/selected-root fields
  and excludes verified checkpoint, signature/key, anchor epoch/rotation, and
  prefix high-water metadata. The v1 beneficiary equals the canonical insured
  subject; no untyped override is accepted. Parametric claims reuse the shared
  `EconomicStateBatchV1`, resource heads, effect slot, and canonical
  liability-coverage ledger, with activation gated until legacy claims use that
  same ledger. Panel authority uses the shared FROST schema and
  payout-instruction v2; v1 stays unchanged.
- WS9: begin with ordinary tests in the owning validator crates. Add a runner
  or crate only when shared campaign code proves a distinct ownership and
  dependency boundary. Project-signed output remains internal qualification.
  Missing-target results are explicit `NotRun`; the two named production
  admission controls must land before Wave 3 entry.
- WS10: a Rust-derived eight-byte big-endian cost key plus sequence/time indexes
  ships in WS10 Phase 2, preserving the full `u64` domain, and the stale claim in
  `docs/reference/AGENT_ECONOMY.md` 3.5.3 is corrected in the same PR.
  Exact-window analytics require the time-index proof; threshold delivery uses
  ordered authority cursors and a leased durable outbox. Webhook mutation
  requires tenant-admin/write authority plus operator-approved egress.
  Policy-input/decision activation additionally requires the externally anchored
  policy and decision-head checkpoint; anchor outage leaves read-only analytics
  available but denies underwriting current use.
- WS6: financial verification uses a sibling policy, local trust registry,
  stable source passport identity, exact presentation binding, complete
  aggregate-source proofs and rollback-independent lifecycle pin; cross-org
  presentation stays asserted. WS6 and WS10 coordinate one strict underwriting
  input version before either new arm ships.
- WS8: fiscal admission is signed and independently anchored; consumer adapters retain
  the declared live units and exact parity domains, with the documented
  fixed-point precision correction. Tier limits bind currency and validity is
  required. Activation remains unavailable until the
  current runtime registry proves every consumer and issuance gate installed,
  preserving one active authority after migration. Snapshot rollback or anchor
  outage fails startup rather than reopening fallback.
- WS1: IOUs use a dedicated `economy.credit.issuer` backend distinct from the
  kernel receipt signer. Remote reconcile reuses the control-plane token and
  exact-authority egress seam.

## Detailed plan index

| Plan | Covers | Status |
|------|--------|--------|
| `2026-07-09-protocol-primitives.md` Task 6 plus corrected RFC-0003 and `2026-07-12-admission-operation-design.md` | Generic AdmissionOperation, projection, nested/top-level boundary, serving fence, cumulative approval participant | written |
| `2026-07-12-frost-quorum-substrate.md` | FROST P1 verifier, P2 durable signing, P3 runtime qualification | written |
| `2026-07-12-economic-state-continuity.md` | External multi-resource heads, adapter, recovery and WS4/WS5/WS7 activation gate | written |
| `2026-07-10-ws1-first-light-phase1.md` | WS1 Phase 1 (real F68/F72 behavior) | written |
| WS1 phases 2-4 | RFC-0013 payment participant, drivers, credit admission, e2e proof | at phase start |
| WS8, WS10 phase plans | Wave 1 | at workstream start |
| WS2, WS3, WS4, WS6 phase plans | Wave 2 pilot and artifact contracts | at wave start |
| WS2/WS4 production, WS5, WS7, WS9 phase plans | Wave 3 | at wave start |

Each plan follows superpowers:writing-plans with focused TDD tasks, exact paths,
concrete verification commands, and scoped conventional commits, and inherits
the Global Constraints above.
