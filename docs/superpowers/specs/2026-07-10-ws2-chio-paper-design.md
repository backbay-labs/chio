# WS2 Design: Chio Paper (receivables factoring)

- Date: 2026-07-10
- Program: agent-economy program, wave 2 (see `2026-07-10-agent-economy-program-design.md`)
- Depends on: `chio_credit::obligation` and WS1 for production settlement
- Claim track: implementation (signed assignment evidence, not a regulated exchange)
- Branch: `chio/ws2-chio-paper` off `main`

## Goal

Assign one outstanding, receipt-backed obligation to one buyer without inventing
ownership or allowing the same obligation to enter two settlement paths. A claim
is eligible only when the signed receipt names the seller as payee, an
authoritative fresh status proof says the obligation is still outstanding, and
the obligor's disposition authority atomically acknowledges the new creditor.
The original receipt remains signed post-action evidence of the authorized tool
call and amount. A fresh capability/policy decision authorizes
`factor.assignment_bind`; the assignment acknowledgement is the authenticated
disposition transition naming the later creditor and settlement destination.

## Ground truth and prerequisites

- `FinancialReceiptMetadata.settlement_status == Pending` is immutable
  receipt-time evidence. It does not prove that the obligation remains unpaid at
  sale time.
- `IouEnvelope.issuer_key` authenticates the configured IOU issuer (kernel or
  dedicated backend), not the creditor. An IOU
  without `EconomicPayeeReceiptMetadata` (`beneficiary_id` and
  `settlement_destination_ref`) does not prove who owns the receivable and is
  ineligible.
- A seller-signed exposure report can support risk analysis, but it cannot prove
  ownership, current settlement state, or non-equivocation. It is never an
  ownership fallback.
- WS2 consumes the program's immutable
  `chio_credit::obligation::ObligationAtom`. The atom is keyed by one stable
  `obligation_id` and binds the receipt digest, debtor,
  `original_creditor` (the receipt's payee), amount, currency, and due date.
  Current creditor is resolved only from
  `chio_credit::obligation::ObligationDisposition`: `assigned` names the
  buyer, while other dispositions retain `original_creditor`. Mutable
  settlement lifecycle and disposition state are authenticated records beside
  the atom, never fields rewritten inside it.
- Completing an assignment requires an authoritative disposition service owned
  or explicitly delegated by the obligor. It must support compare-and-swap and
  emit a signed acknowledgement. A seller-local log is audit evidence only and
  cannot satisfy this prerequisite.

No implementation phase may advertise transferable paper until the payee
binding, fresh status proof, and obligor-authorized compare-and-swap are
available end to end.

## In scope

1. A pure `chio_credit::factor` module with canonical serde artifacts and
   deterministic validation. `chio-credit` already owns IOUs, obligations, and
   underwriting inputs, so v1 adds no crate.
2. One `ReceivableClaim` over exactly one
   `chio_credit::obligation::ObligationAtom`, receipt, and IOU.
3. A direct, bilateral `AssignmentOffer` and `AssignmentAgreement`.
4. A fresh obligor-signed `chio.obligation.status-proof.v1` input and an
   obligor-signed `AssignmentAcknowledgement` produced by the authoritative
   disposition compare-and-swap.
5. A checked, integer-only `DiscountQuote`.
6. Protocol, schema, verifier, unknown-schema negative, and ladder registration
   for `factor.assignment_bind` in the same phase.
7. Settlement reconciliation that pays only the creditor and destination named
   by the current acknowledged disposition.

## Out of scope

- Bundled claims, fractional assignment, secondary resale, supersession, and
  cross-currency claims.
- Offline completion. Artifacts can be verified offline, but a transfer cannot
  complete while the obligor disposition authority is unreachable.
- A seller-authored ownership registry, seller-chain fork detection as a
  correctness claim, optional anchoring as a substitute for compare-and-swap,
  or an exposure-context ownership fallback.
- An order book, matching engine, automated venue, custody, or new Solidity.
- Mainnet or public-testnet deployment and production money movement before
  WS1's durable settlement path is complete.

## Design

### Canonical operation preimage

`NormalizedAssignmentRequestV1` is the only assignment request body hashed into
`AdmissionOperationV1.request_binding_hash`. Its strict RFC 8785 body contains
schema, obligation id and atom digest, claim and offer digests, seller, buyer and
buyer settlement destination, agreed price/currency and discount, expected
disposition and settlement-lifecycle versions, action nonce, effective time, due
time, and request expiry. It excludes `operation_id`, status-proof and assignment
authorization artifacts, agreement/party signatures, result/acknowledgement, and
every other value derived or learned after `Prepared`.

The generic operation id is derived from kind, coordinator/namespace/request,
the already verified base capability id/hash, and the domain-separated digest of
this normalized body. That base capability does not contain the derived operation
id. The coordinator persists `Prepared` first. The fresh
`factor.assignment_bind` authorization and both signatures over
`chio.factor.assignment-agreement.v1` are then verified to bind the derived
operation id and exact normalized-request digest. A canonical
`VerifiedAssignmentAuthorizationSetV1` binds both exact artifact/envelope digests,
and its digest compare-and-swaps once into
`supplemental_authorization_digest`. A mismatch or attempted replacement denies. No implementation hashes a
self-containing signed agreement.

### Eligibility contract

An obligation is assignable only when all of these checks pass at the same
authoritative version:

1. A fresh capability/policy decision authorizes
   `factor.assignment_bind` and binds the atom digest, seller, buyer, action
   nonce, expiry, normalized-assignment-request digest, and a shared
   `AdmissionOperationKind::GovernedEconomicMutation` operation id already
   derived and persisted as described above.
2. The Chio receipt and IOU signatures verify under trusted kernel keys and
   bind the same `receipt_id`, amount, currency, debtor, content hash, and policy
   hash.
3. The receipt's economic envelope contains a payee binding. Its
   `beneficiary_id` equals `seller_id`. Neither `issuer_key`, `tool_server`, nor
   exposure context may be substituted for the payee.
4. The `chio.obligation.status-proof.v1` status proof is signed by the configured
   obligor disposition authority and binds `obligation_id` and atom digest,
   the separate current creditor/disposition record, the separate settlement lifecycle status,
   their versions, `issued_at`, `expires_at`, and `due_at`. The proof is built
   from one transactional snapshot, and its `due_at` must equal the immutable
   atom term.
5. At agreement time the proof is unexpired, `settlement_status == Pending`,
   `disposition == per_call`, the current creditor is the seller, and
   `effective_at < due_at`. A missing or past due date rejects the claim.
6. The authoritative store atomically compares the proof's version and state,
   then changes only that atom's separate disposition record from `per_call` to
   `assigned { agreement_id, creditor_id: buyer_id }`. Any intervening
   settlement, assignment, channel reservation, clearing reservation, or
   version change makes the compare-and-swap fail.

The assignment store uses `operation_id` as its idempotency key and supports
lookup by operation. It is the authoritative
`GovernedEconomicMutation` saga participant and retains a versioned signed
`chio.factor.assignment-acknowledgement.v1` as its applied terminal result, or a
signed `chio.factor.assignment-not-applied.v1` result. The acknowledgement binds
operation, agreement/normalized-request digest, obligor authority/key epoch,
obligation id, expected and resulting disposition version/fence, and its own
acknowledgement id; the terminal result id is that acknowledgement id and its
result digest is the exact signed acknowledgement-envelope digest. The
not-applied family binds the same request/resource identities, prior version/fence,
closed reason, and no-mutation proof. The successful disposition CAS,
acknowledgement envelope, and participant audit event commit in that service's
one transaction. The local AdmissionOperation is not claimed atomic with a
remote or separately stored disposition service.

The coordinator persists `Prepared`, invokes apply once by `operation_id`, and
queries the participant after any ambiguous response. It verifies the signed
result into `VerifiedEconomicMutationApplied` or
`VerifiedEconomicMutationNotApplied`, then uses the matching admission terminal
projection to bind `terminal_result_id`/digest, append the local audit event, and
retain `EconomicMutationApplied` or `EconomicMutationNotApplied`. A matching
retry returns the exact acknowledgement or not-applied envelope bytes. A conflict rejects, and recovery never repeats the
assignment merely because the local operation row is stale. WS2 defines no
parallel coordinator.

The compare-and-swap, not a private history presented by the seller, prevents
double assignment. Of two concurrent agreements for one `obligation_id`, at
most one can receive an acknowledgement.

### Artifacts

Every artifact is RFC 8785 canonical JSON with a versioned schema identifier.
Signed artifacts carry signatures over their canonical bodies. Unsigned
projections are admitted only when their exact canonical digests are bound by
verified signed artifacts.

- `chio.obligation.status-proof.v1` is owned by
  `chio_credit::obligation`, not by the factoring module. Its canonical body
  binds `schema: "chio.obligation.status-proof.v1"`, `proof_id`,
  `obligation_id`, `obligation_atom_digest`, debtor,
  `original_creditor`, resolved current creditor and settlement destination,
  complete disposition value and digest, disposition version, settlement
  lifecycle value and digest, lifecycle version, `due_at`, `issued_at`,
  `expires_at`, authority id, and authority key epoch. Both state records come
  from one transactional snapshot. The configured obligor disposition authority
  signs the RFC 8785 body in a detached signature; verifier trust resolves the
  authority id and active key epoch from runtime configuration, never from an
  embedded key. A future
  timestamp, expiry beyond the configured maximum proof lifetime, inactive or
  mismatched epoch, mixed snapshot versions, or any atom/state mismatch rejects.
- `chio.factor.receivable-claim.v1` binds `claim_id`, `seller_id`,
  `obligation_atom_digest`, `receipt_id` and digest, `iou_id` and digest,
  `payee_binding_digest`, `status_proof_digest`, `face_value:
  MonetaryAmount`, `due_at`, and `built_at`. Exactly one receipt and one atom
  are permitted.
- `chio.factor.assignment-offer.v1` binds the claim digest,
  `asking_discount_bps: u16`, derived `minimum_price: MonetaryAmount`,
  `issued_at`, and `expires_at`. Validation requires
  `asking_discount_bps <= 10_000` and
  `issued_at < expires_at < due_at`.
- `chio.factor.assignment-agreement.v1` binds the offer and claim digests,
  seller, buyer, agreed discount and price, buyer settlement destination,
  `assignment_authority_digest`, expected disposition and
  settlement-lifecycle versions, normalized-assignment-request digest,
  `operation_id`, `effective_at`, and `due_at`. Seller and
  buyer signatures are both required.
- `chio.factor.assignment-acknowledgement.v1` is emitted only after the
  obligor-authorized compare-and-swap succeeds and is signed by that configured
  authority. It binds `acknowledgement_id`, `obligation_id`, agreement and
  normalized-assignment-request digests, old and new
  disposition versions, prior `per_call` disposition, new `assigned`
  disposition, buyer creditor and destination, `assignment_authority_digest`,
  `status_proof_digest`, `operation_id`, resource fence, obligor authority/key
  epoch, `effective_at`, and `due_at`. The acknowledgement id is
  domain-separated RFC 8785 over the complete body except itself.
- `chio.factor.assignment-not-applied.v1` is the signed terminal no-mutation
  result. It binds result id, normalized request/agreement/operation,
  obligation/resource version and fence, authority/key epoch, a closed reason,
  and the exact proof that the disposition did not change.
- `chio.factor.discount-quote.v1` binds the claim, underwriting decision, and
  scorecard digests, `resolved_discount_bps`, quoted price, and an optional
  refusal reason.

The acknowledgement is immutable. Later settlement state is emitted as a
separate reconciliation artifact; no acknowledgement is edited after signing.

### Pricing

All rates are integer basis points and must be in `0..=10_000`. The quoted
price is:

```text
floor(face_value.units * (10_000 - discount_bps) / 10_000)
```

The multiplication uses a checked `u128` intermediate. Overflow, an out-of-range
rate, currency drift, or a result that cannot convert to `u64` rejects the
quote. Arithmetic never wraps or saturates. Risk inputs may raise the discount
monotonically, but `Deny`, `StepUp`, `Critical`, or `Restricted` produces a
refusal instead of a price.

### Assignment and settlement flow

1. Read the atom and a fresh `chio.obligation.status-proof.v1` from the
   authoritative obligor disposition service, and obtain fresh pre-action
   authority for `factor.assignment_bind`.
2. Verify the authority digest, eligibility, and discount quote.
3. Seller and buyer sign the agreement before its offer and status proof expire.
4. Submit the agreement with the expected disposition and settlement-lifecycle
   versions. In one
   transaction, compare-and-swap `per_call` to `assigned` and persist the
   signed acknowledgement. A partial write is an error.
5. The buyer pays the seller outside WS2. WS2 records no claim that payment
   occurred unless separate payment evidence verifies.
6. WS1 settlement resolves the current disposition and may pay only the buyer
   destination bound by the acknowledgement. The per-call, channel, and
   clearing paths must all skip an obligation whose disposition is `assigned`.
7. Settlement emits a separate reconciliation artifact and atomically advances
   the separate settlement lifecycle. It never mutates the immutable atom,
   original receipt, agreement, or acknowledgement.

### Persistence and integration

- `chio_credit::factor` owns only pure validation and derivation.
- `chio_credit::obligation` owns the immutable atom,
  `chio.obligation.status-proof.v1`,
  `chio_credit::obligation::ObligationDisposition`, and store contract.
  `platform/chio-store-sqlite` implements the authenticated compare-and-swap
  and audit for one authoritative deployment, but a seller-controlled replica
  is not authoritative for another obligor.
- `chio-credit` supplies IOU and underwriting inputs. Exposure reports are
  optional risk evidence only.
- `chio-settle` consumes the acknowledged current creditor at execution time.
  A stale redirection intent is not sufficient.
- `spec/PROTOCOL.md` and `spec/CHIO_LADDER.md` must define the
  `factor.assignment_bind` transition and reject unknown disposition states.

### Fail-closed errors

Invalid signature, untrusted signer, missing, stale, or mismatched pre-action
authority, missing payee binding, seller/payee
mismatch, stale status proof, non-Pending state, non-`per_call` disposition,
missing or elapsed due date, mixed currency, amount mismatch, claim digest
mismatch, expired offer, discount above 10,000 basis points, checked-arithmetic
failure, missing counter-signature, compare-and-swap conflict, or missing
obligor acknowledgement rejects the assignment. No error path falls back to a
seller log or exposure context.

## Alternatives considered

1. A new `chio-factor` crate was rejected for v1. `chio-credit` already owns
   the obligation, IOU, and underwriting dependency boundary. Extract only if
   an actual dependency cycle or independent release boundary appears.
2. A per-seller digest chain was rejected as the correctness boundary. A seller
   can present different valid forks to different buyers. The obligor-authorized
   compare-and-swap is the minimum shared serialization point that prevents the
   second transfer.
3. Exposure-context ownership was rejected. It is a seller assertion and does
   not name the receipt's authoritative creditor.
4. Bundles and secondary trading were deferred. One atom and one first
   assignment make ownership, maturity, and settlement routing unambiguous.

## Claim framing

Chio Paper proves a signed assignment acknowledged by the obligor's configured
disposition authority. It is not custody, settlement finality, a security
issuance, or a regulated exchange. Without the acknowledgement, the agreement
is only proposed bilateral intent and must not be described as a completed
transfer.

## Testing strategy

- Authority: missing payee binding, `issuer_key` used as creditor,
  exposure-only ownership, wrong obligor signer, and seller/payee mismatch each
  reject. Missing, expired, replayed, or atom-mismatched
  `factor.assignment_bind` authority also rejects.
- Freshness and maturity: stale proof, already settled lifecycle, absent due
  date, offer expiring at or after maturity, and assignment at maturity each
  reject.
- Non-equivocation: two concurrent agreements use the same expected version;
  exactly one compare-and-swap succeeds and exactly one acknowledgement exists.
- Operation identity: canonical normalized-request round trip; changing each
  economic term changes the request/operation digest, while adding operation id,
  authorization, status proof, agreement signature, or acknowledgement cannot
  enter the preimage. Late authorization/agreement must match and attach once;
  circular or replacement bindings reject.
- Operation recovery: acknowledgement-loss retry returns the exact stored
  acknowledgement id, envelope digest, and bytes by `operation_id`; crashes before and after the disposition
  CAS yield either one signed not-applied result or one completed assignment.
  Crash between participant commit and local terminal projection queries and
  binds the same result; it never repeats the mutation or claims cross-store
  atomicity.
- Exclusive routing: `channelized`, `clearing_reserved`, and already
  `assigned` dispositions reject; an acknowledged obligation is skipped by
  every non-assigned settlement path.
- Pricing: boundary cases at 0 and 10,000 basis points, 10,001 rejection,
  checked arithmetic, deterministic rounding, and currency equality.
- Status proof: canonical positive fixture plus independent field tampering,
  unknown family/schema/version, untrusted authority, stale or future issuance,
  inactive/wrong key epoch, cross-atom replay, and disposition/lifecycle
  mixed-snapshot negatives. Runtime and CLI registry parity is mandatory.
- Schema/verifier: canonical JSON stability, registry parity, unknown-schema
  negatives, tamper negatives, and acknowledgement/reconciliation separation.

## Implementation phases

1. Prerequisite gate: land
   protocol-primitives `GovernedEconomicMutation`,
   `NormalizedAssignmentRequestV1` and its non-circular operation derivation,
   `chio_credit::obligation::ObligationAtom`,
   `chio_credit::obligation::ObligationDisposition`, the SQLite store contract
   implementation, payee-bound producer, and
   `chio.obligation.status-proof.v1` canonical body, schema constant, JSON
   schema, configured-authority signer/verifier, runtime and CLI registry
   entries, signed and tampered fixtures, unknown-schema negatives, fresh
   snapshot producer, and matching `spec/PROTOCOL.md` registry text, then
   operation-owned compare-and-swap, signed obligor acknowledgement/not-applied
   terminal results, and lookup/replay recovery. WS2 stops here if any
   piece is unavailable.
2. Land the pure `chio_credit::factor` claim, offer, agreement,
   acknowledgement, and quote validators with schemas, verifiers, and the
   concurrency proof.
3. Add direct submission and settlement reconciliation. Add venue discovery
   only after one real obligor-to-buyer assignment completes end to end.
