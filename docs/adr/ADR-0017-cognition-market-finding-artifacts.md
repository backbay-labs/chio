# ADR-0017: Cognition-Market Finding Artifacts And Reveal-As-Governed-Call

- Status: Accepted (2026-07-31)
- Implementation record: M0-M6, M8, and M9 implement and qualify the
  single-operator profile. The default-off implementation gate was removed
  after the full workspace qualification gate passed. M7 remains conditional
  and unbuilt because no bilateral deployment has triggered ADR-C. The release
  boundary publishes four scoped claims, preserves two audited assumptions,
  and assigns proof-bundle ownership to `chio-transaction-passport`.
- Decision owner: economy and settlement lane
- Related: ADR-0015 (non-discretionary escrow posture), ADR-0016 (authoritative spend contract), `spec/PROTOCOL.md` 6.4.5 (disclosure and lineage family), `spec/PROTOCOL.md` 6.4.7 (finding artifact family)

## Context

Agent swarms re-derive each other's dead ends because negative results are
never shared, and a finding cannot be shown to a buyer without giving it away
(Arrow's information paradox). Chio already ships the expensive parts of a
market that fixes this: trusted-path metering and budgets, a listing/bid/accept
marketplace whose buyers are agent subjects, bonds with adjudicated slashing,
escrow with two predeclared price-free terminal states, and receipts that bind
an output digest (`content_hash`) under WYSIWYS signing. At proposal time, the
missing pieces were an information-good type and a binding between payment
release and information delivery. The qualified single-operator profile now
supplies the registered type, publication and discovery, governed delivery,
challenge and audit, status and retraction, pool purchasing, and independently
verifiable proof-passport evidence. The memo's gap analysis (Q1-Q8) grounds
the proposal-time claims in file-level evidence.

## Decision

### D1. A finding is a listed good, not a new subsystem

A tradeable unit of cognition is a signed `chio.finding.v1` artifact: a
machine-matchable descriptor (topic, context digest, outcome class), a
sealed-payload commitment (`payload_sha256`) and media type, a guarantee
class plus optional deterministic replay-recipe digest, evidence references
(mediated receipt ids, checkpoint ref, issuer-asserted cost rollup, optional
runtime assurance tier), an evidence class from the normative
`asserted`/`observed`/`verified` taxonomy, typed issuer identity, an opaque
collateral reference, a status-feed reference, optional license and pricing-hint
references, an optional pre-outcome intent-commitment receipt reference, and
an expiry. The verification procedure has the caller check the
registered schema at the raw boundary, run `Finding::validate` for structure
and id/content-address consistency, and run `verify_finding` for the strict
issuer signature. Production admission resolves and authenticates the
required references before a listing can advertise an evidence-backed
guarantee.
Negative results are `outcome_class = null_result`, not a separate type.
Findings are published, discovered, and priced through the existing
`chio-listing` registry (listed under the existing `ToolServer` actor
kind: the closed `GenericListingActorKind` enum is wire-frozen, so the
finding artifact, not a new enum variant, carries the good's identity -
see ARCHITECTURE 7.3) with the existing signed pricing
hint. M2 adds content-addressed Finding storage, a bounded descriptor index,
and a venue-signed admission bundle because the generic listing projection
does not carry these bindings. It does not introduce a second market venue.

### D2. Reveal is a governed tool call; the receipt is the delivery proof

The sealed payload is served by a seller-operated Chio tool server. Purchase
mints a DPoP-required capability for one `read_finding` invocation (existing
bid/ask/accept flow, `max_invocations: 1`, and both per-invocation and total
ceilings equal to the accepted price). The current generic bid path does not
set DPoP, so M4 must add and require `dpop_required: Some(true)`. The
provider, tool, subject, payee, signed ask, signed bid, accepted reservation,
selected grant, and finding commitment are one cross-bound purchase context;
a same-subject substitute token is not enough.
The provider-signed `RequireFindingPurchase` constraint also selects exactly
`LocalReversibleHold` or
`CrossOrgEscrow { settlement_profile_sha256 }`. Local mode rejects an escrow
witness, while cross-org mode requires the exact profile digest and dedicated
witness context key. Missing or conflicting rail evidence denies before
mutation and cannot fall back to local capture.
The reveal happens through the kernel, and the delivery contract is digest
and media-type equality: kernel finalization MUST refuse to emit a payable
Allow delivery receipt whose `content_hash` differs from
`payload_sha256` or whose reveal-envelope media type differs from
`payload_media_type`.

ADR-A must select an output-aware durable payment transition. The current
reserve-for-caller `MustPrepay` path can capture a reversible hold before the
caller receives its reservation, and `PrepaidFinal` can settle before output
exists. Neither is admissible for a digest-constrained reveal as shipped.
The leading one-operator profile is a direct durable `HoldCapture`
authorization whose exact price, currency, payer, beneficiary, and accepted
bid are frozen before dispatch and whose capture occurs only after the
identity-profile output passes both checks. Any pre-capture abort, digest
mismatch, media mismatch, or policy incompatibility persists a signed Deny
and releases the rail hold and budget/exposure reservation idempotently,
exactly once. It cannot capture. Because no transfer was captured, this is a
hold release, not a refund or compensation. A crash after capture resumes the
durably staged matched Allow and recovery authorization; it cannot turn that
capture into a Deny or capture again.

Cross-organization `ChioEscrow` remains conditional on M7's exact
funded-escrow and settlement-authority proofs and is blocked on ADR-C. The
current contract's alternative release methods can bypass an off-chain
full-only and settlement-authority profile. ADR-C must therefore choose a
contract-gated discriminator or classify the existing path as an audited,
Experimental TTP profile with no non-discretionary guarantee. M7 requires a
governance-signed settlement profile and a bond-authority-signed, non-reusable
mediator-backing allocation. Before accept, the stronger reservation authority
first consumes the exact live backing allocation, then observes and freezes
the exact final funding. It binds both settlement-profile and mediator-backing
envelope digests plus the backing-allocation consumption id. After the signed accepted bid
exists, the settlement authority re-observes it and signs the funded witness.
Together they bind the EVM depositor or explicitly authorized sponsor, capital
instruction, refund destination exactly equal to the depositor and
`createEscrow` caller, contract-derived escrow id, seller
beneficiary, exact amount/currency, token address/decimals/config epoch,
mediator, deadline, and finality. The shipped `SignedReservationReceipt` body
contains only agent id, listing, ask digest, and reserved amount; it does not
prove payer key, expiry, replay state, the full purchase context, or funded
state.

After delivery, the signed Finding release decision is committed into the
standard receipt by defining `settlement_reference` as SHA-256 of the RFC
8785 canonical bytes of the strict
`chio.finding.settlement-reference-input.v1` preimage. Its seven lowercase
hex64 fields commit the complete release envelope, funded witness, delivery
proof, accepted bid, purchase context, settlement profile, and mediator
backing. A golden vector freezes the framing. Three distinct proof
stages then precede release: checkpointed and anchored delivery inclusion,
checkpointed settlement-authority receipt inclusion, and typed escrow-root
publication. The Finding profile admits only
an initially unreleased escrow funded for the exact accepted price and exactly
one full terminal: release the full accepted price after all three stages, or
refund the full accepted price after the deadline. Existing
`partialRelease*` methods, a prior partial release, mixed release/refund, and
amount drift are outside the profile and reject. The external watchdog is not
implicit release authority: the shipped escrow requires `msg.sender` to be
the beneficiary, so that exact beneficiary address must submit it; an
operator settlement signature does not delegate caller authority. Timeout refund is
permissionless only after the deadline. The escrow administrator can pause
release while refund remains available, so an admin can force a
pause-through-deadline refund. M7 must treat that administrator and the
watchdog's operator override as explicit trust and SLA risks. Because the
contract permits a zero-value `refund` after a completed full release, the
profile's observer keeps `released == deposited` as the monetary
`FullReleased` terminal, records the later zero-refund flag as state drift,
and never reclassifies or pays it as a second terminal. Rotation away from
the operator key hash frozen in `EscrowTerms` also makes release fail while
deadline refund remains possible. M7 therefore requires that key to remain
valid through terminal settlement or treats rotation-induced refund as a
bonded operator-SLA failure; rotation cannot silently authorize a new release
key. No third contract state is introduced, per ADR-0015 D2.

### D3. Proof claims stay inside the verifier's boundary

A finding's guarantee class MUST be truthful to its backing, mirroring
guarantee-level truthfulness for spend: `deterministic_replay` (claim is
re-checkable by mediated re-execution), `metered_attested` (execution, cost,
and digest are attested; claim semantics are not), or `asserted`. Listings
MUST NOT advertise proof capabilities the buyer-verification boundary
rejects. M1 `verify_finding` verifies artifact integrity only. M2 introduces
a distinct `FindingEvidenceVerifier` that resolves and verifies receipt
bodies and signatures, checkpoint membership, trusted kernel and revocation
state, receipt attribution metadata, authenticated signed capability snapshots
and transport/provider identity, recipe bindings, and
guarantee/evidence-class boundaries. `ReceiptLineageStatementBody` relates
receipt/request endpoints and session anchors; it is not issuer, subject, or
delegation evidence. Listing authority requires a separate issuer-signed
authorization or delegation carrier bound to the exact Finding, listing,
seller, scope, validity interval, and revocation state.

Only qualifying full-receipt evidence can earn independently summed cost
facets. Every receipt body/signature and checkpoint membership proof must
first pass. `metered_exposure_backing` then verifies the admitted kernel,
mediated reconciled exposure, matching signed nonce, and exact-currency
checked sum. `settled_spend_backing` additionally requires qualifying capture
or finalized-settlement evidence. The first is a lower bound on
kernel-accounted metered exposure; the second is a lower bound on
kernel-accounted settled spend. Neither proves paid work, honest computation,
or total effort. A
projected disclosure may authenticate its projection and disclosed fields,
but cannot claim the concealed originals' receipt-authenticity,
checkpoint-membership, or either cost-backing facet. The verifier returns an
explicit per-facet report and never silently upgrades a claim.
Projected authentication uses the externally pinned BBS issuer
fingerprint/key, epoch, trusted registry, validity, rotation, and revocation
policy from the reusable verifier profile. An issuer key embedded in the
projection cannot authorize itself.

`deterministic_replay` is relative to a governance-authorized,
content-addressed verifier profile transitively committed by the replay
recipe. Generic mediated receipts alone do not establish semantic replay.
An effectful governed executor performs the recipe before adjudication; the
pure evaluator only verifies strict role-authorized observations and applies
the recipe's closed predicate. Unavailability, timeout, resource exhaustion,
runner failure, and malformed output are indeterminate and cannot sanction a
seller.

Finding-specific hidden predicates are unsupported. The current
disclosure-lineage registry structurally allowlists a predicate tuple, but
its crypto-context report does not commit to canonical capsule or
hidden-predicate bytes and does not resolve `proof_ref`. A future profile
must add those digest and proof-resolution bindings, plus substitution tests,
before any Finding listing may claim hidden-predicate verification.

### D4. Fabrication is a predeclared slash lane, and only where decidable

The marketplace penalty vocabularies remain frozen at v1. A mechanically
verified finding fraud outcome maps to the existing
`FraudulentListing` abuse class and carries exactly one `External` evidence
reference to a signed, registered `chio.finding.challenge-outcome.v1`
artifact. Signer roles are non-substitutable: a buyer challenge is signed by
the buyer subject with class-specific M4 standing. `evidence_invalid` and
`replay_contradiction` require a pinned finalized purchase record.
`digest_mismatch` instead requires the purchase-authority-signed
`chio.finding.failed-delivery.v1` that binds the accepted bid, authoritative
reservation/payment operation, released hold, checkpointed Deny, zero
realized spend, and payout-ineligible state; no purchase record exists on that
pre-capture terminal. An audit
authorization is signed by the admitted venue scheduler; the outcome is
signed by the profile-authorized outcome authority; the enforcement
authorization is signed by the governance-authorized Finding enforcement
authority; and payout eligibility comes only from purchase records signed by
the admitted M4 purchase-record authority and cross-bound to kernel delivery
and payment evidence. The verifier profile also pins one exact market-penalty
authority. The penalty envelope signer, its `issued_by` identity, and
`governing_operator_id` must resolve to that same admitted governing-operator
role; a merely trusted but differently mapped signer rejects. The profile
pins each role's trusted keys, validity/rotation policy, and
evidence-resolution policy. The `External`
reference MUST name the deterministic `outcome_id` and carry the SHA-256
digest of the complete canonical signed outcome envelope. A
finding-specific enforcement wrapper strict-parses that envelope, verifies
its role-authorized signature, exact id and envelope digest, and all Finding,
listing, purchase, rule, liability, and evidence bindings before it can enter
the existing Sanction gate. A generic caller-selected `External` reference
is never sufficient.

Slashing fires only through the composed new and existing gates. The typed
Finding evaluator must first return a confirmed violation. The resulting
generic Sanction case must then pass `evaluate_generic_governance_case` with
the expected `Sanctioned` effective state, admission block, and no findings
before the ordinary market-penalty evaluator runs. The finding wrapper admits
exactly three typed penalty transitions: an enforced `HoldBond` producing
`BondHeld`; an enforced Appeal that separately passes generic governance
evaluation as `Appealed` with no findings and the exact prior case and
`appeal_of_case_id`, then uses `ReverseSlash` to supersede the prior penalty
only when its action is exactly `HoldBond` and its amount equals the full
unapplied hold; or, after appeal finality, an enforced `SlashBond` producing
`BondSlashed`. Each branch reuses the exact outcome, liability, amount, and
supersession bindings and rejects a generic branch bypass. The generic
evaluator checks only that `penalty_amount` does not exceed the fee
schedule's `required_amount` in the same currency. It does not prove a live
allocation, the computed Finding amount, or the Finding branch's exact
Hold/Slash penalty-state compatibility, so the wrapper requires all three and
exact equality to the computed enforcement amount sealed in the allocation
and enforcement artifact before impairment. Generic acceptance of Hold or
Slash, or a generic `Reversed` state, is not sufficient.

The new Finding coordinator, not the generic penalty gate, owns live
allocation verification, purchase-snapshot and payout derivation, claim and
appeal finality, exact Finding amount, and external-effect publication. The
generic gate verifies governing-authority signatures, generic
case/listing/schedule bindings, action-to-case-kind restrictions, and the
declarative amount ceiling only. The Finding wrapper owns exact penalty-state
compatibility for each transition.

The predeclared decision rules are limited to what is mechanically decidable:
a checkpointed signed Deny proving seller-origin digest mismatch under the
marked identity-output profile; affirmative evidence invalidity under the
verifier profile effective at publication; and, for `deterministic_replay`
findings, a challenger's contradicting mediated re-execution of the exact
committed recipe. Affirmative invalidity means a bad signature,
contradictory checkpoint proof, semantic cross-binding failure, or proof that
a referenced key or artifact was already revoked or invalid at publication.
Resolver unavailability, missing retained bytes, an SLA failure, later key
revocation, and later Finding retraction are indeterminate or status/operator
events, not retroactive seller fabrication. Generic digest mismatches,
wrong-media delivery, and operator-policy transforms are not by themselves
seller-sanction evidence.

Challenge admission is a schema and validator `oneOf`: either a signed
`buyer_submission` with one live class-specific Dispute lock and a collected
dispute-fee receipt, or a role-authorized signed venue-audit authorization
from the committed audit epoch with no Dispute lock, dispute fee, forfeiture,
or reward. Cross-branch fields reject. Venue audits are selected from the
signed epoch snapshot by committed randomness; an honest audit cannot
subsidize a seller. Every evidence class returns the class-independent verdict
`Upheld | Rejected | Indeterminate`. Only replay also carries the nested
predicate result `ConfirmedContradiction | Consistent | Indeterminate`,
mapped respectively to those top-level verdicts. The admitted outcome
authority signs `chio.finding.challenge-outcome.v1` for every verdict. Only
`Upheld` may enter the penalty lane and supply the fraud-outcome evidence.
`Indeterminate` creates no seller hold,
Sanction, impairment, payout, or retraction. A buyer lock may remain through
one bounded signed retry window as `IndeterminateRetryable`; exhaustion or
expiry signs the `IndeterminateClosed` terminal and returns the lock exactly
once. Infrastructure failure never forfeits it.

The first Upheld transition must linearize the sales block, frozen purchase
cutoff, and `Open -> UpheldPendingClaims` incident-head CAS in the same
authoritative transaction or CAS domain as M4 purchase finalization. A
concurrent purchase either finalizes before that cutoff and enters the claim
snapshot, or observes the block and cannot capture afterward.

Appeal handling distinguishes no filing, a signed terminal `Denied` appeal,
and an unresolved or expired appeal. Absence at the filing deadline is proven
from the authoritative appeal index; `Denied` advances to finalization; an
`Open`, `Escalated`, unresolved, or merely expired appeal blocks impairment
until a signed terminal successor resolves it. A successful appeal is an
`Enforced` Appeal whose clean generic evaluation is effective `Appealed`,
nonblocking, and has no findings. Both `appeal_of_case_id` and
`supersedes_case_id` name the exact original Sanction and current
incident/admission head, which advances so the original Sanction no longer
blocks. `ReverseSlash` must also supersede the exact held penalty for the full
unapplied amount. Sanction, Hold, and authority validity must span the claim,
appeal, and finalization horizons or continue through a signed successor
protocol with unchanged incident, allocation, and held-penalty bindings.

Successful independent challengers may receive only capped verified-cost
reimbursement from a pre-collected dispute-fee challenge-administration
pool. The participation-fee pool remains audit-only. Slashed seller
collateral goes only to verified harmed buyers or the registered community
fund. The authoritative payout set and immutable rail-tagged destinations
come from M4 purchase records frozen at the first upheld challenge; neither
challenger input nor challenge-time address resolution may change them.
Until deterministic batching exists, one liability admits at most 15
distinct buyer destinations and reserves the sixteenth vault beneficiary
slot for the community fund. The admitted pre-sale market terms pin the
community-fund identity and rail destination plus the governing registry or
root; the coordinator cannot select a new fund after fraud is found.

The finding-specific signed operator authorization enforces that
harmed-party allowlist and exact allocation before impairment. This remains
an explicit operator trust role: the current bond-vault contract checks
array shape, at most 16 nonzero beneficiary addresses, a nonzero amount not
above remaining collateral, and exact-sum shares, but does not structurally
recognize harmed buyers or the community fund. ADR-0015 follow-up A is still
required for an on-chain harmed-party theorem.

One liability key prevents another seller impairment, while each external
effect has its own domain identity: the unbatched-v1 seller impairment
includes chain, vault, liability, and allocation digest; the challenge-bond
effect includes only challenge and lock, while a separately compared intent
digest commits return/forfeit disposition and amount; fee reimbursement
includes challenge or audit run and fee operation; and the durable
pre-publication retraction intent includes Finding, feed, and
`retraction_intent_id`. M6 epoch/root publication has its own later publisher
attempt identity. A
generic chain/vault/liability/effect-kind tuple is not an adequate key for
non-vault effects. At the appeal-final upheld transition, the coordinator
atomically fences the signed enforcement state, `publication_pending`, and
the retraction outbox intent before dispatching external impairment and
payout. The status-publication effect remains dispatch-ineligible until the
exact impairment is confirmed final. Failure, ambiguity, or quarantine keeps
the pending purchase block without appending an irreversible retraction.

Semantically-wrong-but-honestly-produced findings remain priced risk carried
by bonds, guarantee-class pricing, and reputation; they are not an
adjudication lane.

### D5. Retraction is a status feed on the revocation-oracle pattern

Every finding names a status feed on the revocation-oracle pattern (signed
epoch roots, inclusion and non-inclusion checks). The
oracle key is `RevocationKey { subject_id, epoch_nonce }`, where
`EpochNonce` is a `u64`, so the feed pins one numeric `key_domain_nonce`
selected and documented by M6. `chio.finding.status.v1` is the protocol-domain
label, not the wire value. Every insert and proof uses exactly
`(finding_id, that numeric nonce)` - otherwise a retraction under one nonce
coexists with fresh non-inclusion proofs under another. A separate
monotonically advancing `map_epoch` identifies sparse-root generations. The
status-epoch artifact canonically binds the feed id, fixed key-domain nonce,
map epoch, operator key, sparse root data, backend and proof-semantics version,
anchors, and validity bounds. The outer artifact signature MUST cover that
complete domain binding. Merely embedding today's `SignedEpochRoot` is
insufficient because
its signing preimage has no feed, backend, or semantic domain. Existing
signer and envelope types may be reused only inside this separately signed
outer artifact. Current signed-root verification remains a component check,
but today's append-only ordinary Merkle backend carries no non-inclusion path
and checks absence against the verifier's LOCAL `HashMap`, so its root cannot
support portable absence. M6 adds a domain-separated, versioned true sparse
status-map backend plus a registered strict verifier-input type carrying its
portable path and every feed/key/root binding. Kernel admission verifies
bounded raw proof bytes before writing their digest and root refs into the
signed finding overlay; a CLI check or unauthenticated online answer is not
enough. The qualified portable profile MUST obtain that fresh proof at
purchase time and SHOULD subscribe to epoch roots afterward. A separately
authenticated trusted-query mode may be useful operationally, but it remains
outside the portable overlay and `status_fresh` claim.

Fresh signed roots do not prove insert completeness. Challenge processing
creates no append-only status change before appeal finality. Only the
appeal-final upheld transition atomically persists a publication-pending
marker and idempotent retraction outbox item; purchases deny until a signed
epoch and inclusion proof clear the item. A successful appeal or an
indeterminate/consistent evaluation never enqueues retraction.

The buyer/runtime retains a monotonic latest-observed
`(map_epoch, epoch_id, root_hash)` floor for each feed and pinned operator.
Purchase admission rejects a non-inclusion proof whose signed map epoch is
older than that floor, or whose equal numeric epoch has a different id or
root, even if its timestamp remains inside the nominal freshness window. It
also rejects expired or wrong-domain proofs and verifies the complete signed
epoch artifact, embedded
root signer, feed operator, and configured authenticated resolver against the
same pinned deployment. This prevents rollback to an old valid proof but does
not prove insert completeness.

Voluntary and cross-operator retractions use authenticated intent receipts
plus a bonded inclusion SLA, monitoring, and operator penalty, but operator
completeness remains an audited assumption. Ingestion of purchased payloads
goes through governed memory writes so the provenance chain binds store/key
to the purchase capability and delivery receipt; a policy-selected guard
rule MAY deny reads whose provenance traces to a retracted finding.
Automatic invalidation of derived data is out of scope.

## Consequences

- Positive: the market uses bounded extensions around a new artifact family
  while reusing the settlement, bonding, adjudication, and provenance
  architecture already ratified. The qualified one-operator Arrow flow binds
  payment to delivery without new cryptography.
  Full-receipt evidence can establish a kernel-accounted spend floor only
  after strict receipt/checkpoint verification, authoritative-spend and nonce
  checks, and qualifying capture or finalized-settlement evidence. This is not
  a paid-work claim. Projected evidence cannot inherit those
  receipt/checkpoint/cost facets, and `evidence_cost` alone remains a seller
  assertion.
- Negative: value-versus-content risk remains with the buyer by design; the
  reveal step trusts kernel mediation rather than an atomic swap; disputes
  outside deterministic replay still require a roster-anchored adjudicator;
  pricing negative results remains an open research problem. The launch
  elicitation helper can apply a buyer-local estimate as a ceiling, but the
  shipped `MeteredBillingQuote` is caller-carried data, not an authenticated
  re-derivation quote producer.

## Non-goals

No auction or order book, no PSI or zk-SNARK machinery, no new escrow
contract, no finding-content storage inside Chio, no autonomous adjudication
beyond replay-checkable rules, no permissionless federation semantics (the v1
explicit-gaps posture in `spec/PROTOCOL.md` section 14 is unchanged).
