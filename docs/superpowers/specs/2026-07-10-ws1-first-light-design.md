# WS1 Design: First Light (production money loop)

- Date: 2026-07-10
- Program: agent-economy program, wave 1 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: protocol-primitives Task 6 / corrected RFC-0003 before Phase 2
  (RFC-0006 base is merged, but its serving-owner amendment is part of that
  prerequisite); the 2026-07-12 FROST quorum substrate through
  Phase 3 plus the settlement resource CAS before the Phase 4 release claim;
  Phase 1 is independent
- Claim track: implementation + release gate (RFC-0013 Phase 2)
- Branch: chio/ws1-first-light off main

## Goal

Every money plug point between the kernel and the economic crates is closed in
production, and moved funds imply either an attested receipt or a loud
reconciliation incident. Today the budget store is the only production-wired
plug point; the settlement hook, payment adapters, price oracle, and credit
driver are installed only by tests, and the settlement outcome is dropped at
its single production call site. WS1 closes the two independent defects first,
then wires the production money loop only after the RFC-0003 durability substrate
exists. It also defines the creditor, rail-capability, and exclusive-disposition
contracts that later market work consumes. The final phase proves the loop with
one always-on kernel end-to-end test running the production code paths.

## Context (what exists today)

The kernel assembles its stores through `chio-control-plane` `configure_*`
functions that each take a `(local_db_path, control_url)` pair, install a SQLite
store locally or a remote store, and are mutually exclusive. Only budgets are
covered: `configure_budget_store` (`crates/platform/chio-control-plane/src/lib.rs:528`)
sits beside `configure_receipt_store` (`:389`) and is chained from the CLI runtime
at `crates/products/chio-cli/src/cli/runtime.rs:46`. There is no `configure_*`
for settlement, payment, oracle, or credit.

The kernel exposes setters with no control-plane callers:
`set_settlement_observer` (`crates/kernel/chio-kernel/src/kernel/construction.rs:574`),
`set_payment_adapter` (`:518`), and `set_price_oracle` (`:522`). The charge path
already consumes these fields when present. `check_and_increment_budget`
(`crates/kernel/chio-kernel/src/kernel/validation.rs:775`) durably debits the
worst-case hold via `authorize_budget_hold` (`:810`);
`finalize_budgeted_tool_output_with_cost_and_metadata` (`:927`) reconciles it
(`reconcile_budget_charge` `:906`, called `:1025`), captures or releases through
`self.payment_adapter` (`:1038-1046`), and resolves cross-currency cost through
`self.price_oracle` (`resolve_cross_currency_cost` `:1216`, oracle call `:1230`).
The tool reports actual cost via `invoke_with_cost`
(`crates/kernel/chio-kernel/src/runtime.rs:355`; default `None` charges
`max_cost_per_invocation`).

The settlement observer and retry primitives exist but are incomplete and
unwired. The `SettlementHook` trait
(`crates/economy/chio-settle/src/hook.rs:247`) classifies a `SettlementObservation`
into `SettlementOutcome::{Accepted, Skipped, Retryable, Permanent}` (`:122`); the
observer slot `run_observer` (`crates/kernel/chio-kernel/src/kernel/settlement_observer.rs:161`)
returns `SettlementObserverStatus` (`:33`). The only implementations are test hooks.
The production defect is F68: `record_chio_receipt` binds the observer status to
`_settlement_status` and drops it (`crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs:179`).
The credit side is equally dark: `CreditEvaluatorHook` (`crates/economy/chio-credit/src/hook.rs:130`)
mints a signed `IouEnvelope` (`:94`), `LocalCreditAccount` implements it
(`crates/economy/chio-credit/src/local_account.rs:83`), and `SqliteIouEnvelopeStore`
(`crates/platform/chio-store-sqlite/src/iou_store.rs:42`) persists it, but nothing
in the kernel references any of it. The real `X402PaymentAdapter`/`AcpPaymentAdapter`
(`crates/kernel/chio-kernel/src/payment.rs:205`/`:219`) and the `ChioLinkOracle`
(`crates/economy/chio-link/src/lib.rs:258`) never run live.

`RFC-0013` (`docs/architecture/reliability/RFC-0013-money-path-durability.md`) is
the normative source for the durability layer: the payment journal (F70), hold
sweeper (F71), settlement routing (F68), production driver seam (F69), fail-closed
currency mismatch (F72), durable EIP-3009 nonce store (F73), and `BudgetEnforcer`
caveat (F74). `chio-config` has no economic fields today, and no production
`chio-cli` kernel constructor consumes `ChioConfig`; adding a field there alone
would be unused scaffolding. Live kernels are currently assembled directly in
`cli/runtime.rs`, `cli/mcp/wrap.rs`, and related command modules, while replay
constructs a deliberately isolated kernel.

## In scope

1. The independent F68 settlement-outcome routing correction and F72
   currency-mismatch deny.
2. A control-plane-owned `EconomyRuntimeConfig` selected by an explicit
   `--economy-config` input on live kernel commands, with `settlement`, `payment`,
   `oracle`, and `credit` sections. It lands with the real component installers,
   never in the currently unused `ChioConfig` path. Replay and verification
   kernels expose no economy-config input and remain economy-off.
3. Control-plane `configure_settlement`, `configure_payment_rail`, and
   `configure_price_oracle` functions that validate and install real components.
   An absent block reproduces today's behavior exactly.
4. A production `SettlementHook` installed in the observer slot (routing only) plus
   an async settlement runtime that writes local reconciliation records and
   optionally dispatches to the trust-control reconcile surface.
5. A credit driver in that runtime evaluating explicitly credit-elected canonical
   obligations and their persisted receipts into signed v2 `IouEnvelope` values
   through the production `CreditEvaluatorHook` and `IouEnvelopeStore`. A positive
   paid receipt is not credit eligibility.
6. The RFC-0013 Phase 2 durable money journal (F70), hold sweeper (F71),
   settlement routing consumer (F68), production driver seam (F69), fail-closed
   currency mismatch (F72), durable EIP-3009 nonce store (F73), and
   `BudgetEnforcer` caveat and snapshot seam (F74), following RFC-0013's design.
7. The canonical `chio_credit::obligation::ObligationAtom` projection containing
   one stable `obligation_id`, debtor, `original_creditor`/payee, amount and
   currency, terms, explicit credit election, pre-action authority digest, and
   source receipt digest, plus a durable
   CAS-owned `chio_credit::obligation::ObligationDisposition` (`per_call`,
   `assigned`, `channelized`, or `clearing_reserved`). One obligation may have
   only one active disposition. For a positive outstanding debt, the source
   receipt, retained RFC-0003 operation terminal transition, atom, initial
   disposition, creation event, and attempt-zero work commit through one
   `commit_admission_projection` receipt-writer transaction
   before any observer runs, and one source receipt cannot mint duplicate
   obligations for the same value. The deterministic id preimage and
   source-claim uniqueness key are fixed in the design below.
   Mutable settlement state is a separate signed or authority-authenticated
   sidecar and never rewrites the receipt.
8. A typed rail-capability contract distinguishing final prepayment from
   reversible hold/capture, including idempotency, partial-capture, release,
   refund, and settlement-query support. Callers reject modes a rail cannot honor.
9. Two always-on kernel end-to-end tests through production wiring (mock rail
   endpoints acceptable, production code paths mandatory): a paid-rail case that
   closes its journal and emits no obligation or IOU, and a separately authorized
   credit-facility case that creates one pending obligation and one bound v2 IOU.
   The paid case uses the production FROST verifier and a fixture trusted
   roster/group-key epoch for the ladder's `settle.commitment` authorization; a
   mock quorum verifier is not acceptable.

## Out of scope (explicit cuts)

- Any mainnet or public-testnet deployment, custody, on-chain settlement dispatch,
  or new Solidity. The default settlement driver makes no chain calls. The
  `StablecoinPaymentAdapter` and on-chain settlement remain family-v2 proposals
  gated on external assurance (program invariant 6, ADR-0015).
- Refund or charge reversal. ADR-0006's no-refund model
  (`docs/adr/ADR-0006-monetary-budget-semantics.md:86`) keeps `total_cost_charged`
  monotone; the journal records and reconciles rail movement without inventing a
  refund the kernel does not own.
- RFC-0003's generic retained `AdmissionOperation`, receipt projection, shared
  top-level/nested dispatch boundary, and serving ownership. Protocol-primitives
  Task 6 owns that substrate; WS1 owns only the RFC-0013 payment participant and
  money-specific recovery. RFC-0003 is a hard prerequisite for WS1 Phase 2, not
  an optional boot-orchestration integration.
- Distributed-linearizable spend truth (the ADR-0006 HA overrun bound at `:67`
  stands), and new market artifact families (WS2-WS10). WS1 is substrate only.

## Design

### Components

- Config: `chio_control_plane::economy::EconomyRuntimeConfig` lands with real
  Phase 3 wiring. The already runtime-heavy control-plane crate may reuse
  `chio_link::PriceOracleConfig` directly without pulling `chio-link`'s HTTP and
  Tokio graph into lightweight `chio-config`. `settlement` requires a local
  durable store when `driver = ops` and may also carry an optional remote
  reconcile sink; local persistence and remote delivery are not mutually
  exclusive. `payment` selects a typed rail profile and exact-authority
  `HttpEgressContract`; `credit` names a durable store and issuer backend. The
  file rejects unknown fields and names secret environment-variable references,
  not inline auth tokens.
- Control-plane wiring: `configure_settlement`, `configure_payment_rail`, and
  `configure_price_oracle` (`crates/platform/chio-control-plane/src/lib.rs`) each
  validate and install a real component. No no-op seam is added in Phase 1.
  Payment and oracle dispatch use the repository's typed egress contract, deny
  redirects, and bound response bodies before parsing.
- Production settlement hook (observer slot): a reconciling `SettlementHook` in
  `chio-settle` (`ops.rs`) that `configure_settlement` installs through
  the paired `set_settlement_observer_runtime(hook, outcome_store, retry_policy)`
  API. Its `observe` classifies the observation and returns
  `Accepted`/`Retryable`/`Permanent`, doing only bounded local work. A hook-level
  `Skipped` is invalid because the kernel invokes it only for a positive
  economic observation and routes that shape as permanent failure. It
  returns `Accepted` only after atomically inserting or verifying an idempotent
  open `settlement_reconciliations` work row; it performs no network I/O, never
  re-reads a receipt, and never mints an IOU on the post-persist path, because the
  slot contract forbids blocking dispatch on unbounded hook latency
  (`construction.rs:568`).
- Settlement runtime (F69, `settlement.driver = { none, ops }`, default `none`): the
  async workhorse over persisted settlement work, attempts, obligations, and
  receipts. The Phase 1 F68 foundation makes `settle_attempts` the observer
  outbox; Phase 3 installs its production drain. Whenever the paired observer
  runtime is installed, the receipt-writer transaction seeds a due
  `pending_observation` row with attempt zero for every newly inserted receipt
  before commit.
  The inline observer and
  recovery worker both claim that row by lease and expected version, so a crash
  after receipt commit but before inline routing cannot lose work. Its
  observer-retry worker claims a bounded leased batch from
  `settle_attempts WHERE next_visible_at_ms <= now`, loads each bound receipt,
  re-invokes the hook, and atomically records the next retry or terminal dead
  letter through `chio_settle::SettlementOutcomeStore`. `Accepted` has already
  created the open reconciliation work row and atomically deletes the claimed
  outbox/attempt row; pre-hook `Skipped` deletes it only for a legitimate closed
  skip reason. The paired append seeds work only when it inserts a new receipt;
  byte-identical receipt replay never recreates work after either cleanup path.
  Receipts written before observer installation are not retrofitted by append
  replay. Receipt and outcome store handles must carry the same fixed-size writer
  binding before the runtime can be installed. A
  separate settlement worker claims leased open reconciliation rows, performs
  optional remote delivery, and records the immutable outcome sidecar. The
  credit worker independently scans only canonical obligations whose signed
  economic intent elected `CreditFacility`, that remain outstanding, lack an
  `IouEnvelope`, and have no active or terminal
  credit-attempt row, verifies the bound source receipt, and mints exactly one
  envelope via a `LocalCreditAccount` built with the configured IOU signing
  backend and explicit trusted-kernel-key set
  (`crates/economy/chio-credit/src/local_account.rs:64`). The IOU issuer key comes
  from that backend and is not inferred to be the creditor. The worker persists
  the envelope idempotently through `IouEnvelopeStore`
  (`crates/economy/chio-credit/src/store_binding.rs:48`). Production emits
  `chio.credit.iou-envelope.v2`, binding `obligation_id`, atom digest, debtor,
  original creditor, current disposition digest, amount, currency, due time,
  facility id, and credit-authority digest. Legacy v1 envelopes remain readable
  but are never emitted for the canonical obligation path. Credit evaluation
  failures use a separate `chio-credit`-owned, obligation-keyed retry/dead-letter
  store with bounded leased claims and persisted backoff; they never enter the
  settlement hook's `settle_attempts` queue. A receipt or obligation scan never
  substitutes for draining either due queue. Reconciliation records are local by
  default; a configured `control_url` additionally dispatches to
  `POST /v1/settlements/reconcile` (`docs/reference/AGENT_ECONOMY.md:753`).
  On-chain dispatch is never on this path. Unsigned, untrusted-signer, or
  zero-price receipts mint nothing (`crates/economy/chio-credit/src/hook.rs:132`).
- Durability layer: the existing protocol-primitives `AdmissionOperation`,
  extended by corrected RFC-0003, is the sole request coordinator. RFC-0013's
  `payment_journal` is its operation-keyed payment participant with state
  (`HoldPlaced -> Authorized -> Settling -> Settled -> Closed` for reversible
  holds, `HoldPlaced -> Settled -> Closed` for final prepayment, or
  `ReconcileFailed`), boot
  reconciliation, the open-hold sweeper, the F68 routing consumer
  (`route_settlement_observer_status` plus the settle-owned
  `SettlementOutcomeStore` and SQLite `settle_attempts` outbox/retry
  implementation),
  the F72 currency-mismatch deny, the F73 nonce store, and the F74 snapshot seam.
  These follow RFC-0013's normative invariants; the illustrative F68
  read-then-upsert sequence is tightened into one atomic transaction. The
  bounded dead-letter v1 body is the sole pre-release shape; obsolete unbounded
  bodies and unknown schema tags fail closed. The receipt store advertises a
  typed `AdmissionProjectionCapabilities` set only when its live SQLite schema
  and complete trigger set match the reference manifest. Its one
  `commit_admission_projection` transaction retains the operation terminal row,
  appends the receipt, and applies every required local sidecar. Budget and
  payment participants remain a persisted saga across the separately configured
  budget database; WS1 makes no cross-database atomicity claim.
  Each SQLite database is independently provisioned through RFC-0006's shared
  `SqliteServingOwner`; every mutation/recovery transaction checks that file's
  `(store_uuid, lease_id, owner_epoch)`. The v1 operation, receipt, observer, and
  obligation projection tables must be co-located under the receipt database's
  one writer for the stated atomic projection. A configuration that points an
  obligation projection at another database fails startup. The separate budget
  and payment database has its own serving owner/fence and remains a saga
  participant.
- Economic obligation and disposition: `chio_credit::obligation` owns the atom,
  disposition, authenticated transition event, and store trait;
  `chio-store-sqlite` owns the durable implementation. The projector verifies
  the authorized economic intent and bound source receipt. It derives
  `obligation_id = sha256(canonical_json(["chio.obligation.id.v1",
  economic_intent_digest, source_receipt_digest, 0]))`, where `0` is the only v1
  claim index, and enforces unique `(source_receipt_digest, claim_index)` and
  unique `obligation_id` keys. It binds debtor and
  `original_creditor`/payee explicitly. The intent carries a tagged
  `credit_election`: `NotCredit` or `CreditFacility { facility_id, due_at,
  debtor_id, original_creditor_id, authority_digest }`. The facility variant
  requires fresh `credit.facility_bind` authority and exact party/currency/amount
  agreement; it is never inferred from positive price, pending settlement,
  issuer key, or tool identity. For positive unsettled value, the SQLite receipt
  writer appends the receipt, compare-and-swaps the matching operation to
  `Completed`, inserts the atom, initial disposition, authenticated creation event, and due
  attempt-zero observer-outbox row in one `Immediate` transaction. Positive
  already-settled value appends the receipt, completes the operation, and inserts the
  observer-outbox row in that transaction but creates no live obligation.
  Denied, non-economic, and zero-charge receipts still receive attempt-zero work
  when an observer is installed so the router can durably commit their legitimate
  pre-hook skip; they add no obligation sidecar. If any required insert,
  verification, or terminal compare-and-swap fails, all receipt-side writes roll
  back and the retained operation remains recoverable.
  A later durable compare-and-swap transition appends its audit event and selects
  exactly one downstream settlement mode in one transaction.
  The current creditor resolves only from that disposition; the immutable atom is
  never rewritten. Economy-enabled startup rejects a receipt backend that cannot
  supply the atomic projection contract. Factoring, channel, and clearing work
  cannot infer ownership from `issuer_key`, `tool_server`, or a seller-authored
  exposure report.

### Data flow

1. Quote. A cross-currency draft resolves a rate through the installed
   `PriceOracle` (`resolve_cross_currency_cost`, `validation.rs:1216`), attaching
   `OracleConversionEvidence`. Same-currency drafts skip the oracle.
2. Governed commit. Capability, policy, and guard validation succeed. The kernel
   derives and persists `AdmissionOperationV1::Prepared` before any authoritative
   participant mutation. `authorize_budget_hold`
   durably debits the worst-case hold (`validation.rs:810`) and, in the same
   `Immediate` transaction, writes the `payment_journal` row in `HoldPlaced`.
   The selected rail profile must support the requested settlement mode before
   `adapter.authorize` runs. A typed held result advances to `Authorized`; a
   typed final-prepayment result advances directly to `Settled`, using its
   authorization id as the stable payment reference, and can never enter release
   recovery. Every participant stores the same `operation_id`.
3. Dispatch commit and metered execution. After every participant and pre-tool
   check succeeds, the shared evaluator helper captures invocation reservations
   and durably persists `DispatchCommitted`. Only then may either top-level or
   nested-flow code call `invoke`/`invoke_stream`. The tool reports actual cost
   via `invoke_with_cost` (`runtime.rs:355`).
4. Reconcile. The shared coordinator durably writes the content-addressed raw
   output and insert-once `ToolOutcomeRecordV1`, then compare-and-swaps the exact
   guarded output, reported cost, pricing verdict and settlement disposition.
   For a reversible hold, `reconcile_budget_charge` closes the hold at
   the realized amount (`validation.rs:1025`); the journal advances to `Settling`
   carrying the exact settle intent, the adapter capture/release runs
   (`:1038-1046`), and the journal advances to `Settled`. Final prepayment is
   fixed-price, already `Settled`, and invokes neither capture nor release. A
   crash after tool completion but before `Settling` leaves
   `DispatchCommitted`; recovery queries the transport or freezes the hold as
   `OutcomeUnknownAfterDispatch`. If the outcome record committed, recovery uses
   its exact bytes and cost; otherwise it cannot infer them. It never uses
   `Authorized` alone to release.
5. Durable receipt and obligation. `FinancialReceiptMetadata` is assembled
   (`validation.rs:1114`) and the receipt is signed. The authorized economic
   intent binds the debtor, original creditor/payee, quoted amount, currency,
   requested settlement mode, and pre-action authority digest; the receipt binds
   realized amount and intent digest as post-action evidence. For positive
   receipt, one closed terminal-projection transaction verifies the outcome,
   commits the receipt, compare-and-swaps the exact
   operation to a retained `Completed` tombstone, and, whenever an observer is
   installed, inserts a due
   `pending_observation` attempt-zero row. For economy value the transaction
   additionally verifies the authorized intent and receipt bindings. When the
   value is positive and unsettled it also
   commits exactly one obligation, its initial disposition, and creation event;
   already-settled value has no live obligation, and denied, non-economic, or
   zero-charge value has no obligation. The transaction completes before the
   mediated `Allow` returns
   (ADR-0013 durable-before-allow,
   `docs/adr/ADR-0013-async-receipt-durability.md:17`). The payment participant
   then closes idempotently; either crash ordering is recoverable by
   `operation_id`.
   A projection failure leaves the receipt, obligation sidecars, and outbox row
   absent and the operation nonterminal; recovery resolves it to a receipt or
   retained incident without redispatch.
   A byte-identical duplicate receipt append is a no-op and does not recreate an
   outbox row already removed by a completed observer transition.
6. Settlement observation. After commit, `record_chio_receipt` claims the seeded
   row by lease and expected version, runs the observer outside the receipt-store
   write lock (`receipt_persistence.rs:179`), and routes its outcome (F68).
   `Retryable`, `Permanent`, and hook-failed statuses produce a warning and metric
   plus an atomic `settle_attempts` or `settle_dead_letters` transition.
   `Accepted` means a local open reconciliation work row is durable and deletes
   the outbox row; a legitimate pre-hook `Skipped` also deletes it. A
   hook-returned `Skipped`, integrity/trust failure, or cleanup-store failure is
   unresolved and never collapses to successful cleanup. A crash
   before claim or routing leaves a lease-recoverable due row for the worker.
7. Async processing. The settlement worker drains leased reconciliation work and
   due observer retries. Independently, the credit worker reads the persisted
   obligation and receipt and mints an eligible IOU through its own retry queue.

### Configuration surface

An absent `--economy-config` installs no observer, adapter, oracle, or driver and
yields byte-identical receipts. Effecting production calls still use RFC-0003's
durable admission default. One shared `configure_economy_runtime` assembler
in `chio-control-plane` validates the operation store and required receipt-side
projection capabilities and
atomically installs the hook, outcome store, retry policy, payment adapter,
oracle, credit worker, and background-task handles. Phase 3 migrates every live
builder in `cli/runtime.rs`, the strict MCP wrapper in `cli/mcp/wrap.rs`, and both
new-session and restored-session kernel construction in
`crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/factory.rs` through
the same explicit economy decision. Spawn and restore must apply identical
configuration and recovery state. The replay path in `cli/replay/execute.rs`
remains explicitly economy-disabled and cannot inherit a live config. A
constructor-inventory test names every production, restore, and replay builder so
a new path cannot silently skip the decision.

`driver = ops` requires local durable persistence; an optional remote reconcile
URL additionally requires a token resolved from its configured environment
variable. Payment and oracle endpoints must compile into dispatchable
exact-authority egress contracts. Pre-release qualification first enables
`DurableAdmissionMode::Monetary`; production uses RFC-0003's cumulative
`SideEffecting` default. WS1 does not define an independent journal mode or
default.

### Error handling (fail-closed)

- A monetary call reaching a store without journal support returns
  `BudgetStoreError::Invariant`, never a silent success; a wrong `expected` state
  in `advance_payment_journal` is a `Conflict`-shaped invariant. `settlement_state`
  defaults to `PaymentError::Unavailable`, forcing a boot `ReconcileFailed`
  incident rather than a wrong close.
- `BudgetTree::evaluate` returns `Deny(CurrencyMismatch)` when a spend-capped node
  currency is absent or differs from the draft (F72), realizing ADR-0006's
  cross-currency fail-closed stance (`docs/adr/ADR-0006-monetary-budget-semantics.md:110`).
  A payment authorization present without a configured adapter stays
  `KernelError::Internal` (`validation.rs:1032`).
- IOU minting fails closed on missing credit eligibility, obligation/receipt
  or party binding, paid/satisfied lifecycle, atom/receipt mismatch, signature,
  untrusted signer, or canonical-encoding error
  (`crates/economy/chio-credit/src/hook.rs:28`). The v2 store rejects conflicting
  envelopes by both `obligation_id` and `receipt_id`; `LocalCreditAccount` no
  longer mints from an arbitrary positive allow receipt. Settlement failures
  never roll back dispatch or rewrite a signed receipt; settlement status stays
  advisory in `FinancialReceiptMetadata`.
- A rail mode unsupported by the selected adapter rejects before authorization.
  A configured outbound endpoint that cannot produce a dispatchable
  `HttpEgressContract` rejects at load. Final prepayments are never treated as
  reversible holds, and a local bookkeeping `release` is not described as a
  remote refund.
- Observation construction distinguishes legitimate non-economic/deny/zero
  skips from invalid signature, action hash, signer trust, or positive financial
  metadata. Integrity failures route as typed permanent work. Failure reason
  storage is a closed code plus fixed-size detail digest, retry policy is bounded
  at installation, and accepted/skipped cleanup-store errors are warning-visible
  and counted because stale retry work may remain.
- An old budget hold remains frozen until RFC-0003/payment recovery derives and
  validates a qualifying terminal `RecoveredHoldResolution` carrying the closed
  `MonetaryReleaseAuthority::{NoEffect, ContractualZeroCharge}` and exact durable
  evidence binding. A diagnostic rail status such as `NoAuthorization` or
  `Released` is not independently release authority. Age,
  `ReconcileFailed`, unknown rail state, or a nonterminal journal never reopens
  capacity.
- Missing or conflicting original/current creditor identity, a duplicate active disposition, or
  stale settlement-sidecar evidence rejects. Signed receipt bytes remain
  immutable; later settlement produces a separate reconciliation artifact.

## Alternatives considered

1. Settlement hook target. (A) Local reconciliation records only. (B) Dispatch
   only to the trust-control reconcile surface. (C) Local by default with optional
   remote dispatch. Recommendation: C. The `settlement_reconciliations`,
   `iou_envelope`, and `settle_dead_letters` tables the CLI `chio settle status`
   already reads (`crates/products/chio-cli/src/settle.rs:89-99`) are local, so a
   single-node deployment must work with no control plane; remote dispatch
   reuses the existing authenticated control-plane client machinery without
   making local and remote destinations mutually exclusive. It stays optional
   and token-gated. On-chain is excluded either way by the freeze.
2. Credit driver placement. (A) A new kernel `set_credit_evaluator` observer slot
   invoked in `record_chio_receipt`. (B) Mint the IOU inline inside the observer
   hook, loading the receipt by id. (C) Mint in the async settlement runtime over
   persisted receipts. Recommendation: C. It matches scope item (c) ("persisted
   receipts") and RFC-0013's F69 seam, and keeps the post-persist observer path
   bounded (the slot must not block dispatch, `construction.rs:568`). A is rejected
   by program invariant 4 (no new kernel business logic); B adds receipt re-read and
   signing latency before the `Allow` returns.
3. Durability rollout. (A) Limit durability to monetary calls permanently. (B)
   qualify RFC-0003 under `Monetary`, then release with cumulative
   `SideEffecting` as the fixed production default. (C) Ship only the F68 routing
   consumer and defer the operation coordinator. Recommendation: B. It exercises
   the highest-consequence class first while preventing non-monetary effects from
   bypassing request tombstones in production. `All` remains opt-in for read-only
   replay protection.
4. Configuration timing and owner. (A) Add an economy field to `ChioConfig`,
   which no production CLI kernel builder currently loads. (B) add the
   control-plane runtime config and real shared assembler together in Phase 3,
   selected explicitly by live commands. Recommendation: B. A schema field on an
   unused loader or a seam that always receives `None` proves no behavior.
5. Settlement storage. (A) choose local or remote storage. (B) require local
   durable retry/reconciliation state and optionally deliver the same evidence
   remotely. Recommendation: B. Remote delivery cannot replace restart-safe local
   recovery.

## Claim and release framing

WS1 is implementation within the bounded release posture plus one release gate.
The claim "the production money loop is closed" becomes assertable only when the
RFC-0013 target invariant (moved funds imply an attested receipt or a
reconciliation incident) is enforced by the always-on end-to-end test and F68-F74
are closed. Because `spec/CHIO_LADDER.md` makes `settle.commitment` an `n_of_m`
action, the claim also requires the separately reviewed production FROST
verifier and trusted active roster, group key, key epoch, and rotation rules.
`main` has no such verifier today. Settlement and reconciliation surfaces are
signed intent plus reconciliation evidence, not custody and not finality
(program invariant 7). No public claim widens: the contract freeze and its
external-assurance gate are untouched, the ADR-0006 HA overrun bound stands,
and live capital remains a separate product track. All money is
`MonetaryAmount` in u64 minor units.

## Testing strategy

- Always-on paid-rail end-to-end (release-gate proof): a kernel assembled through
  the production
  `configure_settlement`/`configure_payment_rail`/`configure_price_oracle` path
  with a mock rail endpoint and static oracle drives quote, governed commit,
  metered execution, and settlement observation. It runs the production FROST
  verifier against a fixture trusted roster/group-key epoch and rejects a
  missing, stale, or mismatched quorum. It asserts `DispatchCommitted` precedes
  tool invocation and the operation becomes a retained `Completed` tombstone
  with the receipt and attempt-zero outbox row before observation, the
  reconciliation row exists, the
  `payment_journal` is `Closed`, the hold reconciles to realized amount, and no
  live obligation or IOU exists for captured or prepaid value.
- Always-on credit end-to-end: a separately authorized `CreditFacility` intent
  with no paid rail produces one pending canonical obligation and exactly one
  `chio.credit.iou-envelope.v2` whose obligation, atom, debtor, original creditor,
  facility, amount, currency, and due-time bindings all verify. Removing or
  changing the credit election denies minting. Both tests reuse
  `crates/kernel/chio-kernel/src/kernel/tests/support_monetary.rs`.
- Default-closed invariant: with no `--economy-config`, receipts are byte-identical
  and no settlement, payment, oracle, or credit code runs.
- Rail contract matrix: every unsupported mode rejects before authorization;
  prepaid-final never enters release/capture outcome pricing; redirects,
  unapproved authorities, DNS drift, and oversized responses fail closed.
- Obligation/disposition property: one authorized intent plus its bound source
  receipt produces at most one debtor-original-creditor atom and one active
  disposition under concurrent assignment, channel, and clearing attempts. A
  forced writer failure leaves neither the receipt nor a partial obligation and
  leaves the admission operation nonterminal; an
  observer can see the receipt only after the full receipt/atom/disposition/
  creation/outbox transaction commits.
- Observer crash property: kill after the receipt transaction but before inline
  observer claim; restart leases the seeded attempt-zero row and produces exactly
  one reconciliation or dead letter. Spawned and restored `chio-mcp-remote`
  kernels exercise the same configuration and recovery path.
- RFC-0013 unit and property tests: journal collision fails closed;
  `advance_payment_journal` wrong-state is `Conflict`; the F72 property (no `Allow`
  when a spend-capped node currency is absent or differs); the boot-reconcile
  property (every `request_id` resolves to attested receipt, reconciliation receipt,
  or `ReconcileFailed`, never a silent non-terminal row, never a double capture);
  and a loom model of the routing consumer (no lost attempt row, no double
  dead-letter).
- Crash and soak (load-chaos program, nightly and weekly): SIGKILL between
  `authorize` and receipt commit, after tool return but before `Settling`, and
  between `authorize_budget_hold` and reconcile;
  assert attested-or-incident and swept capacity per RFC-0013's acceptance criteria.
- Path parity and replay: the top-level and nested evaluators produce the same
  operation transitions. Replaying an identical or conflicting completed
  request id returns or rejects from its tombstone without invoking the tool.
- SQLite ownership: a second mutable server open fails, a stale owner epoch
  cannot mutate or recover, and a read-only CLI open starts no worker.

## Implementation phases

Each phase is an independently landable PR ending green at the workspace gate
(`cargo build --workspace && cargo test --workspace && cargo clippy --workspace
-- -D warnings && cargo fmt --all -- --check`).

- Phase 1 (independent fail-closed corrections). The F72 currency-mismatch deny
  and F68 routing consumer replacing the drop at
  `receipt_persistence.rs:179`, with atomic retry/dead-letter persistence and
  `CHIO_SETTLEMENT_UNRESOLVED_TOTAL`. No economy config or no-op installer lands.
  The paired observer installer and durable routing close F68's silent-drop
  defect; the production driver remains F69.
- Phase 2 (durable admission and money participant, RFC-0013 F70/F71;
  hard-gated on corrected RFC-0003 and the protocol-primitives
  `AdmissionOperation`). Protocol-primitives Task 6 owns and lands the retained
  operation store, composable receipt projection, top-level/nested shared
  dispatch boundary, and exclusive SQLite serving lease and epoch fencing.
  WS1 does not reimplement them. This phase adds the RFC-0013
  `payment_journal` participant, `PaymentJournalState`/`PaymentJournalRecord`, the
  defaulted `BudgetStore` journal methods, the `validation.rs` state-machine
  wiring, typed held-versus-final-prepayment authorization,
  `PaymentAdapter` `rail_id`/`settlement_state` additions and boot reconcile, the
  recovery-proven open-hold sweeper (`HoldDisposition::Expired`, sweep task,
  CLI `chio budget holds` review commands, metrics), plus F73
  atomically capacity-bounded `SqliteEip3009NonceStore` and
  F74 `BudgetEnforcer` caveat and snapshot. Qualification begins under
  `DurableAdmissionMode::Monetary`; it does not create another default.
- Phase 3 (production configuration, obligation model, settlement and credit
  driver, RFC-0013 F69). The control-plane-owned `EconomyRuntimeConfig`, explicit
  live-command input, shared assembler, and replay-off constructor inventory;
  the `chio-credit` obligation/disposition contract and
  `chio-store-sqlite` atomic operation-terminal/receipt/atom/
  initial-disposition/observer-outbox implementation; identical configuration
  for CLI, MCP wrapper, and remote MCP
  spawn/restore constructors; the observer-slot `SettlementHook` (routing only);
  `AE-CREDIT-ADMISSION-1` in `chio_credit::obligation` and the same SQLite
  obligation store, with operation-owned reservation, authoritative
  facility/tier exposure CAS, and atomic commit through
  `commit_admission_projection`;
  the async `SettlementRuntime` minting only explicitly authorized v2 credit IOUs
  and writing reconciliation records over persisted receipts, with optional
  trust-control dispatch, behind `settlement.driver = { none, ops }` default
  none; typed rail capabilities and exact-authority egress; the payment adapter
  and existing price-oracle configuration installed from config. The shared
  assembler uses the paired observer API, completing F69 production wiring
  without reopening F68. This phase also owns the settlement-reliability
  evidence substrate used by WS6: persist canonical obligation due-time and
  obligation-id indexes plus terminal reconciliation sidecars, sign
  same-cutoff checkpoint roots under a locally configured source id/key epoch,
  and expose range, predecessor/successor boundary, and unresolved-absence
  proof generation and verification. Restart, gap, duplicate, signer/epoch,
  index-root, and tamper negatives must pass before the substrate advertises
  readiness; a table scan or bounded bundle is not a substitute.
- Phase 4 (end-to-end proof and release gate). The always-on end-to-end test with
  full production wiring and FROST Phase 3, consuming the exact
  `settle.commitment` authorization in the settlement resource version/fence CAS;
  RFC-0003's
  `SideEffecting` production default and the nightly crash/replay/ownership soak;
  F68-F74 closed.
  This phase and the "production money loop is closed" release-gate claim remain
  blocked until that consumer qualification and trusted roster/group-key epoch
  are live.

## Resolved implementation choices

1. Credit uses a dedicated `economy.credit.issuer` signing backend, not the
   kernel receipt key. Credit issuer and creditor identity remain distinct.
   `issuer_key` authenticates
   the IOU envelope; it is not inferred to be the creditor. The signed obligation
   names `original_creditor` separately, and current creditor resolves from the
   disposition. Startup requires the configured issuer id/key epoch and rejects
   an absent backend.
2. Credit-driver discovery is obligation-led. The async runtime scans only
   outstanding obligations carrying the signed `CreditFacility` election, joins
   each to its receipt, and skips any obligation with an IOU or active/terminal
   credit-attempt row. Scanning all priced receipts is forbidden because it would
   mint unrequested credit claims. Credit failures enter their own
   obligation-keyed queue and honor its backoff. The F69 settlement retry worker
   always drains leased due rows from `settle_attempts` and never uses the credit
   scan to bypass `next_visible_at_ms` or a terminal dead letter.
3. The optional remote reconcile path
   (`POST /v1/settlements/reconcile`) reuses
   `configure_budget_store`'s `control_token` seam and the exact-authority
   egress contract. It does not introduce a second token source.
4. Checkpoint boundary in the end-to-end test. The journal and holds live in the
   budget-store database while receipts and checkpoints live in the receipt-store
   database. `AdmissionOperation` is the persisted saga across those participants;
   only the receipt-side projection claims one transaction. The test forces a low `checkpoint_interval`
   (`crates/platform/chio-config/src/schema.rs:118`) and crosses a checkpoint
   boundary to prove durable-before-allow holds under checkpointing.
