# ADR-0017: Cognition-Market Finding Artifacts And Reveal-As-Governed-Call

- Status: Proposed (research spike; see `docs/research/agent-cognition-market.md` for the full analysis this ADR compresses)
- Decision owner: economy and settlement lane
- Related: ADR-0015 (non-discretionary escrow posture), ADR-0016 (authoritative spend contract), `spec/PROTOCOL.md` 6.4.5 (disclosure and lineage family)

## Context

Agent swarms re-derive each other's dead ends because negative results are
never shared, and a finding cannot be shown to a buyer without giving it away
(Arrow's information paradox). Chio already ships the expensive parts of a
market that fixes this: trusted-path metering and budgets, a listing/bid/accept
marketplace whose buyers are agent subjects, bonds with adjudicated slashing,
escrow with two predeclared price-free terminal states, and receipts that bind
an output digest (`content_hash`) under WYSIWYS signing. What is missing is an
information-good type and a binding between payment release and information
delivery. The memo's gap analysis (Q1-Q8) grounds each of these claims in
file-level evidence.

## Decision

### D1. A finding is a listed good, not a new subsystem

A tradeable unit of cognition is a signed `chio.finding.v1` artifact: a
machine-matchable descriptor (topic, context digest, outcome class), a
sealed-payload commitment (`payload_sha256`), evidence references (mediated
receipt ids, checkpoint ref, metered cost rollup, optional runtime assurance
tier), an evidence class from the normative `asserted`/`observed`/`verified`
taxonomy, a slashable bond reference, a status-feed reference, an
optional pre-outcome intent-commitment receipt reference, and an expiry.
Negative results are `outcome_class = null_result`, not a separate type.
Findings are published, discovered, and priced through the existing
`chio-listing` registry (listed under the existing `ToolServer` actor
kind: the closed `GenericListingActorKind` enum is wire-frozen, so the
finding artifact, not a new enum variant, carries the good's identity -
see ARCHITECTURE 7.3) with the existing signed pricing
hint. No new registry, venue, or settlement rail is introduced.

### D2. Reveal is a governed tool call; the receipt is the delivery proof

The sealed payload is served by a seller-operated Chio tool server. Purchase
mints a capability for one `read_finding` invocation (existing bid/ask/accept
flow, `max_invocations: 1`, `max_total_cost` = price). The reveal happens
through the kernel, and the delivery contract is digest equality: the tool
contract MUST refuse a delivery receipt whose `content_hash` differs from the
finding's committed `payload_sha256`. Payment follows the existing settlement
shapes only: kernel `MustPrepay`/hold with refund-on-abort for small amounts,
or `ChioEscrow` whose release is gated on Merkle-proven receipt evidence and
whose only other terminal state is the deadline refund. No third settlement
state exists, per ADR-0015 D2.

### D3. Proof claims stay inside the verifier's boundary

A finding's guarantee class MUST be truthful to its backing, mirroring
guarantee-level truthfulness for spend: `deterministic_replay` (claim is
re-checkable by mediated re-execution), `metered_attested` (execution, cost,
and digest are attested; claim semantics are not), or `asserted`. Listings
MUST NOT advertise proof capabilities the buyer-verification boundary rejects
(`ChioProofClaims`: hidden range predicates, zkVM, and VC-DI-BBS are
unsupported today and are hard-rejected). Hidden-predicate extensions follow
the existing registry-plus-trusted-crypto-context-signer pattern and are
scoped additions, not a general ZK claim.

### D4. Fabrication is a predeclared slash lane, and only where decidable

A new `FabricatedFindingEvidence` abuse class joins the open-market penalty
vocabulary. Slashing fires only through the existing gate: an enforced
governance Sanction case over a slashable bond, amount-capped, with the
appeal/reverse path intact, and distributions constrained to harmed parties or
the registered community fund (ADR-0015 D4). The predeclared decision rules
are limited to what is mechanically decidable: delivered-digest mismatch,
evidence that fails receipt/checkpoint/revocation re-verification, and (for
`deterministic_replay` findings) a bonded challenger's contradicting mediated
re-execution. Buyer-initiated challenges are complemented by venue-funded
probabilistic audits at a published rate, sized so audit-rate times slash
exceeds expected fabrication profit; audit outcomes are ordinary challenge
artifacts (MECHANISMS section 5). Semantically-wrong-but-honestly-produced findings are priced
risk carried by bonds, guarantee-class pricing, and reputation; they are not
an adjudication lane, and no discretionary settlement path is introduced.

### D5. Retraction is a status feed on the revocation-oracle pattern

Every finding names a status feed on a sparse-Merkle revocation oracle
instance (signed epoch roots, inclusion and non-inclusion proofs). The
oracle key is `RevocationKey { subject_id, epoch_nonce }`, so the feed
pins a FIXED domain nonce (`epoch_nonce = "chio.finding.status.v1"`) and
every insert and proof uses exactly `(finding_id, that nonce)` - otherwise
a retraction under one nonce coexists with fresh non-inclusion proofs
under another. Signed-ROOT verification carries over unchanged, but
today's `NonInclusionProof` carries no path bytes and is checked against
the verifier's LOCAL oracle state, so it is not a portable absence proof:
the status feed either extends the oracle with portable sparse-Merkle
non-inclusion paths verifiable against the signed root, or documents its
proof endpoint as a trusted-query surface backed by the operator bond (it
must not label an online answer a signed absence proof). Buyers MUST
obtain a fresh non-inclusion proof at purchase time and SHOULD subscribe
to epoch roots afterward. Ingestion of purchased payloads
goes through governed memory writes so the provenance chain binds store/key to
the purchase capability and delivery receipt; a policy-selected guard rule MAY
deny reads whose provenance traces to a retracted finding. Automatic
invalidation of derived data is out of scope.

## Consequences

- Positive: the market reduces to one new artifact family plus one tool
  contract and reuses every settlement, bonding, adjudication, and provenance
  invariant already ratified; the Arrow flow closes at the
  payment-versus-delivery boundary without new cryptography; fabrication
  economics inherit the metering floor (credible fake evidence costs
  approximately honest work).
- Negative: value-versus-content risk remains with the buyer by design; the
  reveal step trusts kernel mediation rather than an atomic swap; disputes
  outside deterministic replay still require a roster-anchored adjudicator;
  pricing negative results remains an open research problem (the elicitation
  interface bounds bids by the metered re-derivation quote, it does not value
  findings).

## Non-goals

No auction or order book, no PSI or zk-SNARK machinery, no new escrow
contract, no finding-content storage inside Chio, no autonomous adjudication
beyond replay-checkable rules, no permissionless federation semantics (the v1
explicit-gaps posture in `spec/PROTOCOL.md` section 14 is unchanged).
