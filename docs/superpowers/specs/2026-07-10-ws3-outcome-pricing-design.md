# WS3 Design: Verified-outcome pricing

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see `2026-07-10-agent-economy-program-design.md`)
- Depends on: `chio_credit::obligation`, WS1 durable money movement, and a
  genuine hold/capture/release rail before activation
- Claim track: implementation (artifact and evaluator only until rail
  qualification)
- Branch: `chio/ws3-outcome-pricing` off `main`

## Goal

When activation prerequisites are met, price one tool call on a deterministic
predicate over the exact output delivered to the caller. The kernel evaluates
the predicate, binds every pricing input and the delivered output digest into
the signed receipt, and either captures the full held price on pass or releases
the full hold on failure or evaluation error. Until a real reversible rail is
qualified, WS3 ships only artifacts, pre-dispatch binding, and the pure
evaluator. V1 has no prepayment, attempt fee, partial capture, or subjective
adjudication.

## Ground truth and prerequisites

The existing budgeted finalize path can capture an authorized amount or release
an authorization, but no current in-tree `PaymentAdapter` implements a proven
reversible hold. `X402PaymentAdapter` performs prepaid authorization, while both
`X402PaymentAdapter` and `AcpPaymentAdapter` treat later `capture` and `release`
as local bookkeeping. Neither can refund or release remote funds merely because
its local `release` returned success.

WS3 production wiring therefore requires a verified rail capability contract:

- `authorize` reserves funds without settling them;
- `capture` can settle the full reserved amount exactly once;
- `release` actually removes the reservation without charging;
- the authorization remains valid through execution and finalization;
- the authorization binds a rail capture deadline evaluated against the
  receiver anchor's trusted acknowledgement time. An acknowledgement accepted
  by that deadline permanently preserves same-key capture authority until the
  rail reports a terminal result, so recovery can submit or replay capture
  after the deadline without an automatic expiry release; and
- idempotency and reconciliation are covered by WS1's durable journal.

A rail that reports the authorization as already settled, cannot prove release,
or cannot bind payer, payee, amount, currency, and expiry is ineligible.
Therefore the schemas, pure evaluator, receipt binding, and SLA verifier may
land first, but the output-stage hook and all production money movement remain
disabled until a real rail implementation passes the capability and end-to-end
qualification contract below. A mock endpoint or self-declared adapter flag does
not satisfy this gate.

## In scope

1. A pure `chio_listing::outcome` module for the listing-owned predicate,
   pricing validation, evaluator, and SLA arithmetic. Receipt metadata remains
   in `chio-core-types` and penalty admission remains in `chio-open-market`;
   v1 adds no crate.
2. RFC 6901 JSON Pointer selectors with a small deterministic comparator set.
3. One pricing rule: full `outcome_price` on `Passed` and `ZeroCharge` on
   `Failed` or `Unevaluable`.
4. Activation-gated `HoldCapture` requests over an adapter proven to support
   genuine hold, capture, and release.
5. Receipt metadata that binds listing, provider, pricing, predicate, quote,
   delivered output, verdict, and charged amount.
6. An SLA breach artifact whose numerator and denominator are both proven from
   a complete receipt-log range.
7. Schema registration, public verifier coverage, unknown-schema negatives, and
   PROTOCOL reconciliation in the same phase.

## Out of scope

- `MustPrepay`, `AllowThenSettle`, prepaid x402, attempt fees, escrow attempt
  fees, partial capture, and any adapter whose unused balance is only local
  bookkeeping.
- JSONPath, guard-verdict predicates, user code, regex, WASM predicates,
  floating-point comparisons, or model-judged outcomes.
- New Solidity, mainnet or public-testnet deployment, and production money
  movement ahead of WS1.
- Automatic SLA slashing. A breach artifact is complete evidence submitted to
  the existing governance path, not authority to move funds.

## Design

### Predicate vocabulary

`chio.outcome.predicate.v1` contains a non-empty AND-list of assertions. Each
assertion has an RFC 6901 `pointer` and one comparator:

- `exists`;
- `eq` or `ne` against an attached JSON value, compared by RFC 8785 canonical
  bytes; or
- `lt`, `lte`, `gt`, or `gte` against an attached JSON integer, with both
  operands parsed by checked integer conversion.

The empty pointer selects the whole document. Invalid escape sequences,
duplicate assertions, non-integer ordered operands, numeric overflow, missing
targets, invalid JSON, and unknown comparators are deterministic errors.
`exists` passes on any selected value. All other missing targets fail. The
predicate has no extension or reserved execution form in v1.

Evaluation returns `Passed`, `Failed { reason }`, or
`Unevaluable { reason }`. `Failed` and `Unevaluable` both produce zero charge.
The distinction is receipt evidence only.

### Artifacts and receipt binding

All signed artifacts use RFC 8785 canonical JSON with
`deny_unknown_fields` and versioned schema identifiers.

- `chio.outcome.predicate.v1` binds `predicate_id`, assertions,
  `provider_id`, `issued_at`, and `expires_at`.
- `chio.outcome.pricing.v1` binds `pricing_id`, `provider_id`,
  `predicate_id` and digest, `outcome_price: MonetaryAmount`,
  `failure_mode: zero_charge`, optional `sla_digest`, `issued_at`, and
  `expires_at`.
- `chio.outcome.sla.v1` binds provider and listing digests,
  `max_failure_bps <= 10_000`, `minimum_sample_count > 0`,
  `window_seconds > 0`, a fixed window anchor, `effective_at`, and
  `expires_at`. The provider signs the SLA commitment referenced by the listing
  and pricing artifacts.
- `VerifiedOutcomeRequestV1` is the typed `verified_outcome` extension on
  `MeteredBillingContext`; its canonical body uses schema
  `chio.outcome.request.v1` and binds listing id/digest, provider-binding digest,
  pricing id/digest, predicate id/digest, optional SLA digest, and the trusted
  receiver-binding digest. `billing_unit = "verified_outcome"` requires this
  extension, and the extension is forbidden for every other billing unit. The
  whole extension is part of the canonical `ToolCallRequest` binding. Signed
  artifact envelopes resolve through trusted stores by these digests; they are
  not accepted from `GovernedTransactionIntent.context` or another free-form
  field.
- `chio.outcome.eligibility.v1` is a pre-dispatch kernel-signed record. Its
  canonical body binds `schema: "chio.outcome.eligibility.v1"`,
  `eligibility_id`, `request_id`, capability id, tool server and tool name,
  provider id, listing id and digest, provider-binding digest, pricing id and
  digest, predicate id and digest, quote digest, optional SLA digest, exact
  `outcome_price`, `HoldCapture`, request-extension digest, pre-action authority
  digest, exact post-guard policy digest, trusted receiver-binding digest,
  `delivery_ack_deadline`, qualified rail identity/capability digest, rail
  capture deadline, `issued_at`, and `expires_at`. The delivery deadline cannot
  exceed any referenced artifact validity window or the rail capture deadline.
  The receiver binding resolves the kernel or edge key plus the
  rollback-independent delivery-anchor identity/namespace authorized to own the
  delivery slot; an embedded acknowledgement key or caller-selected anchor is
  never a trust root. The kernel signs the RFC 8785 body only after validating
  every referenced artifact and before dispatch. The signed artifact envelope
  contains that body and its detached signature; `eligibility_digest` is SHA-256
  over the RFC 8785 canonical envelope. `eligibility_id` is SHA-256 over the
  domain-separated canonical body excluding `eligibility_id`; the verifier
  recomputes it before accepting the envelope. The record is evidence of the
  selected pricing contract, not a replacement for capability, policy, or guard
  authority.
- WS3 reuses the generic provider-attempt family in `chio-core-types` and the
  closed `DispatchStatusProvider` verification boundary in `chio-kernel`. It
  adds no outcome-specific dispatch checkpoint, acceptance, cancellation,
  execution-lease, or completion schema. `ProviderAttemptBindingV1` binds the
  operation, attempt, transport and key epoch.
  `chio.provider-invocation-blob.v1` binds the canonical request digest, which
  already includes the WS3 request extension and eligibility digest.
  `chio.provider-attempt-checkpoint.v1` then carries the immutable
  `Pending -> Accepted -> Executing -> Completed` chain or the terminal
  `Pending -> Cancelled` branch using `chio.provider-acceptance.v1`,
  `chio.provider-execution-lease.v1`, `chio.provider-completion.v1`, and
  `chio.provider-cancellation.v1`. The qualified transport's provider identity
  and key epoch must match the trusted listing binding. Only
  `VerifiedProviderAccepted`, `VerifiedProviderCompleted`, and
  `VerifiedProviderNotAccepted` returned by that generic verifier are WS3
  evidence. A local queue query, missing row, timeout, old signed status, or
  restored, behind, divergent, unavailable, or unqualified provider view is
  `Unknown`, never acceptance or no-effect authority.

Provider handoff uses the cross-store protocol `LocalQueuedStaged ->
DispatchAnchorAccepted -> LocalExecutable`. A staged row is permanently
non-executable until a worker reads the exact current external `Accepted`
checkpoint and wins its `Accepted -> Executing` lease/fence CAS. If
`Pending -> Cancelled` wins, every matching staged row becomes permanently
non-executable. Recovery reads the anchor before local queue state. An anchored
`Accepted` row whose local queue was rolled back is reconstructed from the
anchored invocation blob; it is never cancelled. After invocation, the provider
stores the terminal result for authenticated lookup before `Executing ->
Completed`. A crash after an effect but before `Completed` may resume only from
authenticated tool-side status or through a separately qualified idempotent tool
invocation keyed by the same operation, attempt, and execution fence. Without
one of those proofs it remains `Executing`/unknown and does not rerun. Stale
executors are fenced and cannot publish a terminal result.
- `chio.outcome.delivery-acknowledgement.v1` is signed by the trusted receiver
  kernel or edge only after the rollback-independent caller-owned delivery slot
  stores the exact final bytes and atomically advances `Pending -> Acknowledged`,
  and before it exposes them to the agent. It binds `ack_id`, request id,
  eligibility and generic provider-acceptance digests, final output digest,
  receiver-binding digest, delivery id and idempotency key, receiver queue id,
  trusted `delivery_accepted_at`, receiver key id/epoch, exact
  delivery-checkpoint sequence/digest, and durable blob reference. The anchor
  retains restart-queryable retrieval by delivery id,
  so a crash or local mailbox restore after acknowledgement cannot strand paid
  output or reopen cancellation. At `Pending -> Acknowledged`, the verifier
  checks the receiver key epoch, eligibility, pricing, quote, delivery deadline,
  and rail capture deadline against the anchor's trusted
  `delivery_accepted_at`. That
  historical validity decision is permanent. Recovery verifies the same
  checkpoint and `delivery_accepted_at`; later wall-clock expiry of an artifact
  or key does not invalidate an acknowledgement that was valid when anchored.
  The signer resolves from the pre-dispatch receiver binding. A socket write,
  HTTP response completion, or caller-supplied key does not qualify.
- `chio.outcome.delivery-nonacceptance.v1` is a receiver-signed terminal
  cancellation proof for the same exact request, eligibility, provider
  acceptance, output digest, receiver binding, delivery id, idempotency key and
  receiver queue. The receiver creates it only after the external delivery anchor
  compare-and-swaps the slot from `Pending` to permanently `Cancelled`, proves no
  blob was accepted or exposed, and makes every later write for that delivery key
  reject. It binds the exact cancellation checkpoint sequence/digest. A private
  verifier constructs `VerifiedReceiverNoDelivery`; missing, timed-out or
  unreachable acknowledgement is not this proof.

The `ReceiverDeliveryAnchor` is outside the receiver SQLite/mailbox backup and
restore domain. Its signed `chio.outcome.delivery-checkpoint.v1` binds anchor and
receiver identity, namespace, delivery slot/idempotency key, monotonic slot
version and predecessor digest, state `Pending | Acknowledged | Cancelled`, exact
request/eligibility/acceptance/output bindings, optional content-addressed blob
reference/digest, trusted-clock high-water, and receiver key epoch. The anchor
stores acknowledged blobs durably or verifies a rollback-independent blob-store
availability receipt before advancing.

A private `VerifiedReceiverDeliveryAdvance` enforces one legal transition
(`Absent -> Pending`, `Pending -> Acknowledged`, or `Pending -> Cancelled`),
exact predecessor, version plus one, nondecreasing clock, and unchanged bindings.
`Pending -> Acknowledged` requires the exact durable blob and
`Pending -> Cancelled` requires a blob-absence proof and cancellation fence. The
anchor accepts only this verified type by linearizable compare-and-swap. Delivery
uses `LocalStaged -> AnchorAdvanced -> LocalFinalized`; exposure is forbidden
until the anchored `Acknowledged` state and local view agree. Recovery reads the
anchor first. A local snapshot that is behind or divergent is repaired from the
anchored blob or fails closed; it can never sign nonacceptance. Anchor outage or
an unresolved staged transition is `delivery_unknown`, with no capture or
release.
- `chio.outcome.verdict.v1` receipt metadata binds:
  `listing_id`, `listing_digest`, `provider_id`,
  `provider_binding_digest`, `pricing_id`, `pricing_digest`,
  `predicate_id`, `predicate_digest`, `quote_digest`, `eligibility_digest`,
  `provider_acceptance_digest`, tagged `delivery_disposition: acknowledged |
  cancelled | not_attempted`, optional `delivery_acknowledgement_digest`, optional
  `delivery_nonacceptance_digest`,
  optional `delivered_output_digest`, `verdict`, `reason_code`,
  `sla_attribution: provider | caller_policy | platform`, `charged_amount`, and
  `rail_authorization_ref`.

The provider binding identifies the trusted key that must sign the listing,
predicate, and pricing artifacts. The request quote digest covers the entire
canonical `MeteredBillingQuote` and its verified-outcome references. A matching
identifier without a matching digest rejects. Receipt metadata is part of the
kernel-signed receipt and cannot be filled from a tool-server self-report.
`acknowledged` requires the acknowledgement digest and forbids a nonacceptance
digest. `cancelled` requires the verified nonacceptance digest and forbids an
acknowledgement digest. `not_attempted` requires both absent and a durable
terminal pre-delivery zero-charge reason. `delivery_unknown` emits no receipt
and cannot be encoded as one of these dispositions.

For an outcome-priced request, the same receipt-store transaction that creates
the RFC-0003 `AdmissionOperation::Prepared` row also persists the canonical
signed eligibility record and writes its digest into the canonical request
binding. The digest is mandatory for this
request class and null for unrelated calls. A duplicate request id with
different eligibility bytes, a missing record, a digest mismatch, an unknown
schema or version, or an untrusted kernel signer denies before dispatch. The
operation and record commit together, so a crash can leave both or neither,
never an unattributed outcome-pricing operation. The eligibility record starts
`prepared`. After authorization and every pre-tool check succeeds, the kernel
must durably compare-and-swap it to `dispatch_started` immediately before the
qualified transport handoff. This is platform state, not provider SLA evidence.
Only generic `VerifiedProviderAccepted` or `VerifiedProviderCompleted` evidence
may transition the row to `dispatch_accepted`, recording the provider-acceptance
digest and the exact anchored `accepted_at`.
Receipt commit must supply its digest in the typed
`AdmissionTerminalProjection::Completed`, match the same digest in signed
`chio.outcome.verdict.v1` metadata, and atomically move the record to
`receipt_bound` with the receipt id while retaining the completed operation. The
signed verdict must bind the same acceptance digest. Terminal crash reconciliation from
`dispatch_accepted` becomes a provider incident; `dispatch_started` without a
recoverable acknowledgement creates a platform incident but remains unresolved
and makes SLA proof incomplete. Only an authenticated server `NotAccepted`
result carrying the current external permanent `Cancelled` checkpoint may
terminate it as `not_dispatched`. A pre-tool abort or recovery moves `prepared` to
`not_dispatched`; that proof is retained but excluded from provider SLA math.
The resolved record and retained terminal operation must agree.

WS3 further extends the operation-owned eligibility lifecycle after provider
acceptance:

```text
dispatch_accepted -> output_ready -> delivery_started
dispatch_accepted -> contractual_zero_ready -> receipt_bound
output_ready -> contractual_zero_ready -> receipt_bound
delivery_started -> delivery_acknowledged -> receipt_bound
delivery_started -> delivery_cancelled -> receipt_bound
delivery_started -> delivery_unknown
delivery_unknown -> delivery_acknowledged -> receipt_bound
delivery_unknown -> delivery_cancelled -> receipt_bound
delivery_unknown -> incident_bound
```

`output_ready` binds the immutable final post-guard bytes and digest.
`delivery_started` binds the exact externally anchored `Pending` slot checkpoint.
`contractual_zero_ready` binds a terminal `ToolOutcomeRecordV1`, a recomputable
`VerifiedContractualZeroCharge`, a closed reason code, and proof that no delivery
slot was opened; its receipt disposition is `not_attempted`. The transition to
`receipt_bound` occurs only after WS1 proves the exact release terminal.
`delivery_acknowledged` stores and verifies the canonical receiver
acknowledgement. Only that state may commit capture, and it instead commits a
contractual-zero release for `Failed` or deterministic `Unevaluable`.
`delivery_cancelled` requires `VerifiedReceiverNoDelivery`, constructs the exact
contractual-zero release authority, and emits a zero-charge receipt only after
release is terminal. A missing, invalid-at-acceptance, ambiguous or unqueryable
acknowledgement moves to recoverable `delivery_unknown`, records an observation,
freezes the hold and emits no receipt. Recovery must query the external anchor
first. A current valid `Acknowledged` checkpoint advances to
`delivery_acknowledged`; a current valid permanent `Cancelled` checkpoint
advances to `delivery_cancelled`; unavailable, pending, behind or divergent state
remains `delivery_unknown`. Neither terminal anchor state can return to unknown
or change branch. Only after the configured recovery policy exhausts all
qualified queries may recovery advance to `incident_bound` and retain
`OutcomeUnknownAfterDispatch`; the hold remains frozen. Such ambiguity is
neither capture nor release authority. A crash after acknowledgement but before
capture reuses the same operation, delivery id and rail idempotency key. Because
the rail evaluates its capture deadline against the permanent anchored
`delivery_accepted_at`, first submission and replay remain valid until terminal,
and capture occurs at most once.

### Exact output-stage ordering

The only valid order is:

1. Require and validate the typed `VerifiedOutcomeRequestV1` extension. Resolve
   and verify the listing, provider binding, predicate, pricing, quote, optional
   SLA, receiver binding, and validity windows by exact digest.
2. Require `MeteredSettlementMode::HoldCapture` and a qualifying rail. Select a
   delivery acknowledgement deadline no later than any artifact expiry or the
   rail capture deadline. Build and verify `chio.outcome.eligibility.v1` with
   those deadlines and the rail qualification digest. Atomically persist it with
   RFC-0003's `AdmissionOperation::Prepared` and bind its digest into the
   canonical request binding. Authorize an unsettled hold for exactly
   `outcome_price`; the authorization must echo the same capture deadline and
   permanent post-ack recovery guarantee. Durably record it before dispatch.
3. After every pre-tool check succeeds, capture invocation admission and durably
   persist `AdmissionOperation::DispatchCommitted`. Compare-and-swap eligibility
   from `prepared` to `dispatch_started`, append its immutable lifecycle
   event, then invoke only the qualified durable-acceptance transport. If that
   commit fails, do not invoke transport; reconcile the hold and terminate as
   `not_dispatched`.
4. Pass the generic `ProviderAttemptBindingV1` and canonical request digest to
   the qualified transport. Accept only generic `VerifiedProviderAccepted` or
   `VerifiedProviderCompleted` evidence returned after immutable local staging,
   rollback-independent invocation-blob availability and external `Accepted`
   checkpoint CAS. Persist the generic acceptance and checkpoint digests plus
   anchored `accepted_at`, then compare-and-swap `dispatch_started` to
   `dispatch_accepted`. If the acknowledgement is lost, recovery uses the same
   `DispatchStatusProvider` query by exact operation and attempt. Only generic
   `VerifiedProviderNotAccepted` over a current permanent `Cancelled` checkpoint
   proves nonacceptance; anchor outage, local restore, or any behind or divergent
   view remains unresolved. Until acceptance is proven, any terminal incident is
   platform-owned and excluded from provider SLA math.
5. The provider worker reads the current external `Accepted` checkpoint, wins
   `Accepted -> Executing` with a fresh execution lease/fence, and only then may
   invoke the tool. Await its authenticated terminal output and retain the raw
   bytes before advancing the anchor to `Completed`. A crash in `Executing`
   queries the exact tool-side idempotency key; absent qualified status or
   idempotent replay, it remains unknown and does not invoke again.
6. Resume the existing durable post-return evaluation record and run the
   complete post-invocation guard pipeline once. A durable block or escalation
   sets `delivered_output_digest = None`, records
   `Unevaluable { reason: output_blocked }`, advances to
   `contractual_zero_ready`, and never opens a delivery slot. A redaction
   produces the final output bytes and uses `sla_attribution = caller_policy`.
   Guard-runtime, evaluator-state, store, or replay ambiguity freezes the hold;
   no free-form guard label can assign provider fault or construct release
   authority.
7. For an allowed output, freeze the final post-guard bytes and digest, then
   evaluate the predicate over the JSON parsed from those same bytes. `Passed`,
   `Failed`, and deterministic `Unevaluable` all advance to `output_ready` and
   delivery; the disposition table determines settlement only after delivery is
   resolved.
8. Run no output mutation after predicate evaluation. Any component that would
   transform the output after this point is an ordering violation. It persists a
   durable contractual-zero outcome, advances to `contractual_zero_ready`, and
   never starts delivery. If that terminal record cannot be persisted, freeze
   rather than infer release authority.
9. Persist `output_ready` with the final output digest and start the qualified
   two-stage delivery. The receiver verifies the binding, creates the exact
   external `Pending` slot, stages the bytes, advances the delivery anchor to
   `Acknowledged` with rollback-independent blob availability, finalizes its local
   view, checks `delivery_accepted_at` against both bound deadlines, signs and
   durably stores `chio.outcome.delivery-acknowledgement.v1`, and only then
   exposes bytes retrieved from that slot to the agent. The delivery remains
   retrievable by id across restart or local snapshot restore. Once anchored,
   acknowledgement validity is historical and permanent.
10. Persist and verify the current anchored delivery state. For
    `Acknowledged`, compare-and-swap to `delivery_acknowledged`; for a valid
    anchored cancellation, construct `VerifiedReceiverNoDelivery` and advance
    to `delivery_cancelled`; otherwise advance to recoverable
    `delivery_unknown`. Derive exactly the action in the disposition table. A
    later wall-clock expiry does not turn an anchored acknowledgement into
    unknown. Ambiguity freezes the hold and stops without a receipt.
11. Persist and execute only that durable rail action through WS1. A `Passed`
    capture carries the permanent acknowledgement and `delivery_accepted_at`, so
    the rail applies the capture deadline to that time and keeps first
    submission, query, and replay available until terminal. Pending remains
    recoverable; an incompatible result incidents and never produces a receipt.
12. After capture or release is terminal, build and sign one receipt whose
    financial charge, all bound digests, output digest, delivery disposition and
    its required acknowledgement, nonacceptance or no-slot evidence,
    attribution, verdict, and rail reference agree.
13. Use RFC-0003's `commit_admission_projection` to verify the eligibility,
    acceptance, delivery, verdict, and payment evidence, transition eligibility
    to `receipt_bound`, append the receipt, and retain the operation as
    `Completed` in one receipt-side transaction. Any mismatch rolls back every
    local projection.

The bytes hashed for predicate evaluation are byte-for-byte the bytes durably
accepted at the receiver boundary. Capture cannot precede that acknowledgement.
The predicate never evaluates a pre-redaction output while charging for a
different delivered result.

### Request and disposition contract

A verified-outcome request has `billing_unit = "verified_outcome"`,
`quoted_units = 1`, `quoted_cost == outcome_price`, and
`settlement_mode = HoldCapture`, and the typed `verified_outcome` request
extension described above. `MustPrepay`, `AllowThenSettle`, a missing extension,
an extension on another billing unit, and any digest mismatch reject before tool
execution.

After generic provider acceptance, the following table is exhaustive:

| Durable terminal evidence | Delivery disposition | Receipt verdict | Rail action | Charged amount | Receipt |
|---|---|---|---|---:|---|
| Valid anchored acknowledgement plus `Passed` | `acknowledged` | `Passed` | `Capture(outcome_price)` | `outcome_price` | yes, after capture is terminal |
| Valid anchored acknowledgement plus `Failed` | `acknowledged` | `Failed` | `Release(VerifiedContractualZeroCharge)` | zero | yes, after release is terminal |
| Valid anchored acknowledgement plus deterministic `Unevaluable` over deliverable bytes | `acknowledged` | `Unevaluable` | `Release(VerifiedContractualZeroCharge)` | zero | yes, after release is terminal |
| Current anchored `Cancelled` plus `VerifiedReceiverNoDelivery` | `cancelled` | `Unevaluable { reason: delivery_cancelled }` | `Release(VerifiedContractualZeroCharge)` | zero | yes, after release is terminal |
| Durable pre-delivery contractual-zero outcome with no delivery slot | `not_attempted` | stored terminal zero-charge verdict and reason | `Release(VerifiedContractualZeroCharge)` | zero | yes, after release is terminal |
| Missing, invalid, pending, unavailable, behind or divergent delivery evidence | none | none | none | hold frozen | no |

For a cancelled delivery, an evaluator result computed before delivery remains
bound audit evidence but is not a billable `Passed` result. Generic pre-dispatch
and provider-nonacceptance compensation remains governed by WS1's
`VerifiedNoEffectProof` paths and is outside this post-acceptance table. No other
combination may capture, release, or emit an outcome receipt.

The rail capture deadline is distinct from quote, pricing, eligibility, and
acknowledgement artifact expiry. It is checked once against the delivery
anchor's trusted `delivery_accepted_at`. If that time is within the deadline, the
qualified rail must preserve the same authorization and idempotency key for
first capture, query, and replay until a terminal capture result, even when
recovery occurs after the deadline. It may not auto-release that authorization
because wall-clock time advanced. If no rail can guarantee this behavior, WS3
production settlement remains disabled.

The hold capture is the per-call settlement attempt, not a precursor to a
second observer dispatch. Zero charge creates no atom. A rail result already
proven `Settled` creates no live atom; if an immutable audit atom is retained,
its separate settlement lifecycle is initialized as `satisfied` in the same
durable transaction. A `Pending` capture may create one immutable
`chio_credit::obligation::ObligationAtom` with an authenticated
`chio_credit::obligation::ObligationDisposition` record set to `per_call`, but
its lifecycle is `settlement_in_flight` and binds the existing capture
idempotency key. Observers may only reconcile that exact operation and must not
start another dispatch. `assigned`, `channelized`, or `clearing_reserved` is a
conflict and prevents the WS3 capture path from running.

### SLA completeness proof

`chio.outcome.sla-breach.v1` binds a provider, listing, pricing, predicate,
declared SLA digest and terms, and the exact closed interval derived from that
SLA's anchor and window cadence. A submitter cannot choose a favorable subrange.
It contains:

- the configured trusted receipt-checkpoint authority key and epoch;
- signed start and end checkpoint digests under that authority;
- the first and last log positions;
- a complete range proof covering every receipt position in the interval;
- the signed RFC-0003 dispatch/recovery checkpoint for the same cutoff, its
  append-only lifecycle-event consistency proof, and the complete global
  provider-acceptance-time range for the declared interval with boundary
  leaves. The proof includes each signed `chio.outcome.eligibility.v1` envelope,
  the generic provider-attempt checkpoint chain and authenticated acceptance,
  plus the acknowledgement or nonacceptance delivery envelope when present,
  stable eligibility sequence, every
  required lifecycle version and incident class, and bound
  receipt or incident id, plus the corresponding retained admission-operation state,
  so a crash after dispatch cannot vanish from the denominator merely because no
  normal receipt was appended. The verifier, not the submitter, applies the
  provider selector to this complete range;
- the checkpoint's global unresolved-`dispatch_started` root and count, which
  must be zero in v1 before any SLA breach proof is accepted. This conservative
  gate prevents a lost or unavailable acknowledgement outside a chosen range
  from hiding a provider-accepted request;
- the fixed eligibility selector
  (`provider_binding_digest`, `listing_digest`, `pricing_digest`, and
  `predicate_digest`);
- the complete eligibility-record root and count, `accepted_count`,
  `provider_attributable_count`, `caller_policy_excluded_count`,
  `platform_excluded_count`, `provider_failure_count`, and references for every
  accepted receipt or terminal incident. The three attribution partitions must
  sum exactly to `accepted_count`; and
- `failure_bps`.

The verifier pins the checkpoint signer and epoch from trusted configuration,
checks checkpoint signatures, authority epochs, append-only event-prefix
consistency, state-root replay, time-range boundaries, and counts. It verifies
that both receipt and eligibility ranges have no missing position, verifies
every eligibility and acceptance signature plus authenticated lifecycle
version, and enforces exactly one terminal binding per record. `prepared`,
`not_dispatched`, `dispatch_started`, and platform-incident records have no
provider-acceptance-time leaf. Terminal `not_dispatched` records are excluded;
an unresolved `dispatch_started` record makes any potentially overlapping proof
incomplete; v1 enforces this as a global zero-count gate. They remain visible in
the record/event roots so exclusion cannot hide an accepted request. A
`dispatch_accepted` record must have its exact digest-bound nonterminal operation and makes
the corpus incomplete until terminal. A
`receipt_bound` record must resolve its recorded receipt id and
the receipt's signed verdict metadata must carry the same eligibility,
provider-acceptance, and disposition-required delivery digests or absence proof.
A provider-class `incident_bound` record must resolve its
  recorded terminal incident, signed acceptance, and retained operation incident.
A platform-class incident cannot enter the acceptance index. It joins by request
id and digest without double counting,
then replays the selector from the eligibility bodies and
recomputes every partition and count. A missing, tampered,
unknown-schema, expired-at-dispatch, or
selector-mismatched eligibility record makes the corpus incomplete and rejects
the breach artifact; it is never silently excluded. The denominator is
every provider-attributable matching request in the declared window. Provider
attribution is limited to an unmodified delivered provider output that passes or
fails the predicate, invalid provider JSON, or a post-acceptance provider
incident. Guard block or byte-changing redaction is `caller_policy`; delivery,
guard-runtime, evaluator, store, and ordering failures are `platform`. Those
rows remain visible and counted in their excluded partitions but enter neither
the provider numerator nor denominator. An unresolved operation or delivery
state makes the corpus incomplete; a provider-attributable terminal
outcome-unknown incident counts as failed rather than disappearing. Failure
receipts alone are never a valid denominator. An unavailable range proof,
untrusted checkpoint authority, gap, duplicate request or position, zero or
below-minimum denominator, SLA/window mismatch, or ineligible receipt rejects
the artifact.

`failure_bps = provider_failure_count * 10_000 /
provider_attributable_count` uses
checked `u128` arithmetic and must be at most 10,000. It is a display value and
never saturates. Breach authority uses the exact checked cross-product, not the
floored display value:

```text
provider_failure_count * 10_000 > max_failure_bps * provider_attributable_count
```

The artifact is a breach only when that inequality holds and
`provider_attributable_count >= minimum_sample_count`. Thus one provider failure
in three attributable requests breaches a 3,333 bps maximum, while one in four
does not breach an exact 2,500 bps maximum.

### Fail-closed errors

Missing or expired artifacts, a missing or misplaced typed request extension,
missing or tampered outcome eligibility, untrusted eligibility signer,
operation/eligibility mismatch, untrusted or mismatched provider signatures,
identifier/digest mismatch, quote mismatch, non-`HoldCapture` mode, prepaid or
unproven rail semantics, missing post-ack capture recovery, authorization or
deadline mismatch, unknown comparator, invalid pointer, malformed artifact JSON,
output-stage reordering, missing or untrusted receiver binding, an
acknowledgement invalid at its anchored `delivery_accepted_at`, a replayed or mismatched
delivery acknowledgement, invalid delivery-nonacceptance or cancellation fence,
capture before acknowledgement, release on delivery ambiguity, charge above the
hold, mixed currency, arithmetic failure, a second dispatch for an in-flight
capture, incomplete SLA range, untrusted checkpoint authority, insufficient
sample, threshold mismatch, and disposition conflict all reject. A final output
that is not valid JSON produces deterministic `Unevaluable` rather than this
artifact-validation error. A runtime predicate
evaluation error after dispatch requests release only after the post-return
journal durably records terminal `Unevaluable` and constructs
`VerifiedContractualZeroCharge`; an ambiguous or non-replayable evaluation
freezes the hold. Until release is proven, reconciliation stays Pending or
Failed. It never records a full charge.

## Alternatives considered

1. A new `chio-outcome` crate was rejected for v1. `chio-listing` already owns
   provider-signed listing pricing; `chio-core-types` and `chio-open-market`
   retain their existing receipt and penalty boundaries. Extract only if a real
   dependency or release boundary appears.
2. Prepayment was rejected because a later local `release` is not a refund.
   Add it only after a configured rail proves outcome-contingent refund
   semantics and WS1 journals that refund.
3. Attempt fees were rejected because they require proven partial capture and
   release of the remainder on every rail. Zero or full capture is the only
   portable v1 contract.
4. JSONPath, guard-verdict predicates, and WASM were deferred. RFC 6901 plus
   deterministic comparators covers the first useful case without a second
   evaluator or ABI. Existing post-invocation output guards remain mandatory.
5. Failure-only SLA evidence was rejected because a provider can omit
   successful or failed receipts and change the rate. A complete checkpointed
   range is required.
6. Outcome-specific provider dispatch schemas were rejected. The generic
   provider-attempt bindings, checkpoint chain, qualified status verifier and
   release proof already define that trust boundary; WS3 only binds its request
   and eligibility digests into the generic attempt.

## Claim framing

A `Passed` verdict means only that the exact delivered JSON satisfied the
declared deterministic predicate. It does not prove objective value or factual
correctness. The verdict is kernel-observed receipt evidence. Escrow and payment
payloads remain subordinate rail evidence. No production outcome-priced payment
claim exists until a real reversible rail passes the activation qualification;
the current in-tree adapters do not. It also requires a qualified two-stage
receiver path; returning output and receipt in one `ToolCallResponse` is not
durable delivery acknowledgement.

## Testing strategy

- Predicate table tests for pointer escaping, root selection, missing paths,
  canonical equality, checked integer ordering, invalid numbers, and unknown
  comparators.
- Eligibility: signed canonical positive; mutate each provider/listing/pricing/
  predicate/quote/authority/request-extension digest independently; reject an
  absent extension for `verified_outcome`, an extension on another billing unit,
  free-form-context substitution, unknown family/schema/version, untrusted
  signer, duplicate request with different bytes, missing operation binding,
  missing record, deadline mismatch, and a record committed separately from its
  operation. Creation assigns stable record/event sequences and a
  version-zero `prepared` event. Tool dispatch cannot run before the durable
  `dispatch_started` CAS, but that state alone is platform-owned. Only generic
  `VerifiedProviderAccepted` or `VerifiedProviderCompleted` evidence from the
  qualified, provider-bound status verifier produces `dispatch_accepted`.
  Receipt commit with the right eligibility, provider-acceptance, and
  disposition-required delivery digests or absence proof atomically produces
  `receipt_bound` and retains the completed operation; a missing or wrong
  verdict/key digest, stale version/lifecycle, or changed envelope rolls back
  both plus the receipt append. Pre-tool failures produce retained
  `not_dispatched` evidence and never enter the SLA numerator or denominator;
  terminal reconciliation after acceptance atomically produces a provider-class
  `incident_bound`; pre-acceptance handoff failures produce platform incidents,
  and ambiguous acceptance remains unresolved until a trusted query resolves it.
  Resolved records remain queryable with the terminal operation; only creation of
  a `prepared` record without its operation rejects.
- Rail matrix: no current in-tree adapter activates WS3. A future genuine
  unsettled hold passes only after networked authorize/capture/release,
  idempotent replay/query, amount, payer, payee, currency, release, and durable
  reconciliation qualification. Acknowledgement before the bound rail capture
  deadline must still permit first capture and replay after that deadline until
  terminal; acknowledgement after the deadline rejects; wall-clock auto-release
  after a valid acknowledgement fails qualification. Already-settled
  `X402PaymentAdapter`, `AcpPaymentAdapter` local bookkeeping, missing release
  proof, missing post-ack capture recovery, expired authorization before
  acknowledgement, and binding mismatch reject before dispatch.
- Provider transport matrix: no generic in-tree tool server activates WS3. A
  future server passes only after durable enqueue before acknowledgement,
  exact-once/idempotency-key enforcement, provider-key binding, and the generic
  rollback-independent `ProviderAttemptCheckpointV1` chain, whose signed
  checkpoints bind the exact operation, attempt, predecessor, version and
  terminal outcome. The invocation blob, acceptance, cancellation, execution
  lease and completion must use the existing generic provider-attempt bindings;
  no WS3-specific checkpoint family is accepted.
  Local queue staging must be non-executable until the external `Accepted ->
  Executing` lease/fence CAS, and external `Cancelled` must permanently fence the
  staged row. Accepted invocation bytes remain reconstructible outside the local
  queue restore domain.
  Acceptance-loss recovery must read the current external `Accepted` or
  `Completed` checkpoint. Nonacceptance requires the current permanent external
  `Cancelled` checkpoint and its cancellation fence. In-memory enqueue, socket
  acceptance, unsigned acknowledgement, wrong
  provider/eligibility/parameter digest, local queue absence, an old checkpoint,
  and a behind, divergent or unavailable anchor cannot create acceptance or
  no-effect evidence. Race staged enqueue against cancellation and executor claim
  against cancellation; exactly one external CAS wins and a cancelled row never
  executes. Crash and restore the provider before and after local stage, external
  acceptance, executor claim, tool effect, terminal-result persistence and
  completion CAS. After an effect but before `Completed`, only authenticated
  tool-side status or qualified idempotent invocation may finish the same
  attempt; otherwise the operation remains `OutcomeUnknownAfterDispatch` with
  its hold frozen and is not rerun. A restored local database can never
  manufacture `NotAccepted`.
- Receiver delivery matrix: the receiver kernel durably stores the exact bytes
  in the rollback-independent anchored slot before acknowledgement and exposure.
  Wrong receiver key/epoch, anchor identity/namespace, checkpoint predecessor,
  slot version, request,
  eligibility, acceptance, output digest, delivery id, or replayed
  acknowledgement rejects. A crash after acknowledgement but before capture
  resumes one capture. Verify validity against anchored
  `delivery_accepted_at`: an acknowledgement valid then remains valid after later
  artifact or key expiry, while one accepted after either bound deadline rejects
  permanently. A lost or unqueryable acknowledgement freezes the hold and
  remains unresolved. Only a receiver-signed no-delivery result created
  atomically with a
  permanent anchored cancellation tombstone releases. Forged, stale, wrong-key,
  wrong-delivery, post-acceptance and replaceable cancellation proofs reject.
  Crash and restore the receiver to every point before and after blob stage,
  anchor CAS, local finalize, signed ack, and exposure. A restored pre-ack local
  snapshot observes the anchored acknowledgement and cannot cancel; an anchor
  outage, pending, behind or divergent view remains `delivery_unknown`. Recovery
  tests cover `delivery_unknown -> delivery_acknowledged`,
  `delivery_unknown -> delivery_cancelled`, repeated unknown, and terminal
  incident, and prove neither terminal anchor state can return to unknown.
- Ordering: predicates see redacted delivered bytes; a durable guard block and a
  post-predicate mutation enter `contractual_zero_ready` with `not_attempted` and
  never open delivery; ambiguous evaluation freezes instead of releasing; the
  receipt output digest equals the acknowledged bytes.
- Pricing: an acknowledged pass captures exactly the quoted price; fail,
  unevaluable, and verified cancelled delivery release the entire hold;
  durable pre-delivery zero releases with `not_attempted`; delivery-unknown
  freezes it and emits no receipt. One table test covers every row and proves no
  other state/action pair validates. No code path emits an attempt fee. A
  settled capture creates no outstanding atom, and a pending capture can only
  reconcile its original idempotency key.
- Binding: mutate each of listing, provider, pricing, predicate, or quote digest
  independently and assert denial.
- SLA: omit, duplicate, or reorder one receipt or eligibility position and
  assert rejection; prove the attribution partitions sum to `accepted_count`,
  provider numerator and denominator recomputation, and the 0 and
  10,000 basis-point boundaries. Wrong checkpoint signer/epoch, cherry-picked window, insufficient
  sample, and an exact rate at or below the declared maximum are not breaches.
  Fractional boundaries prove the cross-product rule: 1/3 breaches 3,333 bps,
  and 1/4 equals but does not breach 2,500 bps. Lifecycle tests mutate or omit an
  event version, state-root leaf, acceptance-time-index boundary,
  prior-checkpoint digest,
  unresolved-started root/count, or sequence and reject. Any nonzero unresolved
  count rejects the SLA proof. A pre-authorization failure, authorization denial,
  and confirmed release before `dispatch_started` remain visible as
  `not_dispatched` but do not change the denominator. A crash immediately after
  `dispatch_started` becomes a platform incident and blocks SLA proof until an
  external current `Accepted`, `Completed`, or permanently `Cancelled` dispatch
  checkpoint resolves it. A restored local `NotAccepted`, missing provider row,
  or unavailable, behind or divergent anchor leaves it unresolved; a crash
  after verified durable `dispatch_accepted` is incomplete until terminally
  reconciled. Guard block/redaction and platform/delivery failures remain visible
  in excluded partitions; only a provider-attributable incident counts as a
  provider failure. Omitting any partition leaf rejects. A request prepared in one SLA
  window and accepted in the next belongs only to the latter.
- Exclusive routing, schema registry parity, public verifier positives,
  unknown-schema negatives, and the workspace gate.

## Implementation phases

1. Land the typed `VerifiedOutcomeRequestV1` extension and pure
   `chio_listing::outcome` predicate, pricing, eligibility,
   delivery-checkpoint, delivery-acknowledgement, delivery-nonacceptance, verdict,
   attribution, and SLA validators with schemas, runtime/CLI registry parity,
   signed/tampered fixtures, and unknown-schema negatives.
2. Add the atomic RFC-0003 operation/eligibility binding, reuse the generic
   provider-attempt lifecycle and qualified status verifier, and add the pure
   exact-output evaluator. Keep the output-stage payment hook disabled.
3. Only after a real rail passes genuine reversible-rail qualification,
   anchored-time capture-deadline enforcement and permanent post-ack recovery,
   and a provider transport passes durable enqueue, signed acceptance, exact
   idempotency, non-executable local staging, rollback-independent invocation
   blob and dispatch-slot continuity, executor lease/fencing, external
   acceptance/completion/cancellation status query, restart-after-enqueue,
   restart-after-execution, and lost-ack qualification, and a receiver path
   passes rollback-independent slot/blob continuity,
   durable-store-before-expose, signed acknowledgement/nonacceptance, status-query,
   crash/restore, anchor-outage, and wrong-binding qualification, enable the hook. Wire
   full-capture/zero-release through WS1's durable participant plus the RFC-0003
   acceptance/delivery lifecycle, and add the always-on
   receipt/output/rail/acceptance/delivery proof. No current in-tree adapter,
   generic tool server, or one-stage `ToolCallResponse` satisfies this phase entry.
4. Add SLA aggregation only after complete checkpoint range proofs exist.
