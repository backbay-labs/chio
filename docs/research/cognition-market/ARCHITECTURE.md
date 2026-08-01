# Cognition Market Architecture

- Status: research draft (branch `research/cognition-market`)
- Basis: [spike memo](../agent-cognition-market.md) gap analysis (Q1-Q8) and
  [ADR-0017](../../adr/ADR-0017-cognition-market-finding-artifacts.md)
  decisions D1-D5, both grounded in file-level evidence
- Companions: [THREAT-MODEL.md](THREAT-MODEL.md), [MECHANISMS.md](MECHANISMS.md),
  [PLAN.md](PLAN.md)
- Discipline: paths cited for every claim about existing code; new surfaces
  are sketches and say so; sections 6-8 record the integration facts that
  determine the final shape, with the chosen option and its rationale

## 1. Purpose and scope

This document turns ADR-0017 into a buildable architecture: the artifact data
model, the six market flows, the exact kernel enforcement points, the service
and deployment topology, and a crate-level integration map. It covers both
instances - coding-agent verified fixes (the wedge) and R&D negative results
(the vision) - as profiles of one design, and marks every place the profiles
differ.

Out of scope, by design (memo 6.8): auctions/order books, PSI or zk-SNARK
machinery, new escrow contracts, finding-content storage inside Chio,
autonomous adjudication beyond replay-checkable rules, permissionless
federation.

## 2. Design principles

Inherited from Chio and treated as constraints, not preferences:

- **Fail-closed everywhere**: a verification error is a denial, never a
  widening (`AGENTS.md` conventions; policy rejection at load).
- **No discretionary value movement**: every settlement terminal state is
  predeclared and price-free; slash destinations are constrained (ADR-0015
  D1-D5, invariants 9/10).
- **Evidence-class truthfulness**: `asserted` never silently becomes
  `verified` (P10; `spec/PROTOCOL.md:620-623`); guarantee classes are
  truthful to their backing (`receipt/authoritative_spend.rs` pattern).
- **Proof claims inside the verifier boundary**: nothing is listable under a
  proof capability the buyer verifier rejects (`ChioProofClaims`,
  `crates/trust/chio-attest-buyer-core/src/claims.rs:12`).
- **Additive schema evolution**: new fields are optional and
  signature-safe; new families are new schema ids, not mutations of frozen
  ones (section 7).

New principles this design adds:

- **Reveal is a governed tool call.** Delivery-versus-payment reduces to the
  kernel's existing receipt machinery; no new exchange protocol exists.
- **The meter is the spam filter.** Every credibility signal (evidence,
  reputation, wash resistance) bottoms out in metered cost.
- **Price the residual, never fake the proof.** What cannot be verified
  (semantic truth of a null) is carried by bonds, guarantee-class discounts,
  and reputation - explicitly, in the artifact fields.

## 3. System overview

```
 SELLER SIDE                          VENUE / TRUST SERVICES                    BUYER SIDE
 ------------                         ----------------------                   ----------
 producer agent                       listing registry (chio-listing)          buyer agent
   | evidence receipts                  - finding listings + pricing hints       | elicitation ceiling
   v                                    - search by context digest               v
 finding assembly ---publish--------->  trust activation (bond-backed)        discovery + offline verify
   |                                                                            (chio-attest-buyer)
   | sealed payload                   finding-status oracle                      |
   v                                  (chio-revocation-oracle instance)          | non-inclusion check
 finding tool server                    - epoch roots, (non-)inclusion           v
 (read_finding, seller-run)             - anchored via chio-anchor             bid/ask/accept
   ^                                                                           (chio-open-market)
   |  mediated reveal call            penalty + governance lane                  |
   +----------------------------+     (chio-open-market + chio-governance)       | reserved funds
                                |       - FabricatedFindingEvidence              v
 KERNEL(S) - the TCB            |       - sanction -> bond impair            read_finding call
   capability verify            |     escrow + rails (chio-settle,               |
   budget hold (MustPrepay)     +---    ChioEscrow/ChioBondVault,            delivery receipt
   guard pipeline                       x402/ACP adapters)                       |
   digest-gated delivery check                                               governed memory write
   receipt signing (content_hash)                                            (provenance chain)
```

Every arrow that moves value or authority is an existing rail; the three new
boxes are the finding artifact family, the finding tool server contract, and
the status-oracle instance.

## 4. Artifact data model

Schema ids proposed (registration path in section 7):

| Schema | Kind | New/reuse |
|---|---|---|
| `chio.finding.v1` | signed information-good artifact | new |
| `chio.delivery-contract.v1` | generic receipt metadata block on any output-committed Allow (M3) | new |
| `chio.finding.delivery.v1` | finding overlay metadata block (M4 purchase binding; optional `status_proof` sub-block added at M6) | new |
| `chio.finding.challenge.v1` | bonded challenge artifact | new |
| `chio.finding.status-epoch.v1` | status-feed epoch root envelope | new (wraps oracle `EpochRoot`) |
| `chio.marketplace.bid-request.v1` etc. | purchase handshake | reuse unchanged (`crates/economy/chio-open-market/src/bidding.rs:33-42`) |

### 4.1 `chio.finding.v1`

Field table (types follow the Rust sketch in the memo, section 6.1; all
structs `deny_unknown_fields`, canonical JSON, Ed25519-signed like every
signed export envelope in the economy crates):

| Field | Type | Semantics |
|---|---|---|
| `schema` | string | `chio.finding.v1` |
| `finding_id` | string | content-addressed: sha256 of the canonical body with `finding_id` AND `signature` both cleared - the single canonical id input, identical to the implementation plan's `compute_finding_id` |
| `descriptor.topic` | string | prefix-searchable topic key (org- or repo-scoped) |
| `descriptor.context_sha256` | hex64 | digest of the full context object (committed test suite + commit, or experiment protocol); the match key |
| `descriptor.outcome_class` | enum | `null_result` / `verified_fix` / `positive_result` |
| `guarantee_class` | enum | `deterministic_replay` / `metered_attested` / `asserted` (truthful-to-backing; D3) |
| `payload_sha256` | hex64 | commitment to the reveal: digest of the canonical reveal ENVELOPE, not raw payload bytes (normative definition in 4.5) |
| `payload_media_type` | string | e.g. `application/json`, `text/x-diff` |
| `evidence_receipt_ids` | [string] | producing receipts (must verify fail-closed) |
| `evidence_checkpoint_ref` | string | checkpoint containing the evidence receipts |
| `evidence_cost` | {units, currency} | metered production cost rollup; verifiable against receipts only in full-receipt evidence mode (F2 mode A) or after audit - in projected mode this value is a seller assertion (MECHANISMS 1) |
| `runtime_assurance_tier` | enum? | tier from appraisal if the producing runtime was attested; the existing CLOSED vocabulary `none`/`basic`/`attested`/`verified` (`chio-core-types/src/capability/runtime_attestation.rs:15-23`) so unsupported tier names fail at parse time |
| `evidence_class` | enum | `asserted` / `observed` / `verified` linkage class of claim-to-evidence |
| `replay_recipe_sha256` | hex64? | REQUIRED for `deterministic_replay`: digest of the committed re-execution recipe (tool server id, tool, parameter template, expected verdict predicate) |
| `intent_commitment_receipt_id` | string? | receipt id of a pre-outcome intent commitment: a mediated call that committed the descriptor/protocol digest BEFORE the producing run completed. Optional but priced, so it earns the `guarantee_class_bps` uplift ONLY when the buyer/publisher SEMANTICALLY verifies it (review finding; the M1 validator only checks non-empty, which is not enough for a priced field): the referenced receipt must resolve, its `timestamp` must precede every `evidence_receipt_ids` receipt, and its `action.parameter_hash` must commit to this finding's `descriptor.context_sha256`. An unverified id earns no uplift (Registered-Reports logic, MECHANISMS 8.4) |
| `bond_ref` | string | open-market bond requirement id with `slashable: true` |
| `status_feed_ref` | string | oracle feed id where retraction state is published |
| `license_ref` | string? | out-of-protocol license terms digest (B2 in threat model) |
| `price_hint_ref` | string? | the signed `ListingPricingHint` id |
| `issuer` | pubkey | producing agent subject (must be consistent with evidence lineage) |
| `issued_at` / `expires_at` | u64 | validity window |
| `signature` | sig | over canonical body |

Example (wedge instance):

```json
{
  "schema": "chio.finding.v1",
  "finding_id": "f3a9...",
  "descriptor": {
    "topic": "repo:backbay/chio#test-failure",
    "context_sha256": "9c41...",
    "outcome_class": "verified_fix"
  },
  "guarantee_class": "deterministic_replay",
  "payload_sha256": "b7e2...",
  "payload_media_type": "text/x-diff",
  "evidence_receipt_ids": ["r-8812...", "r-8813..."],
  "evidence_checkpoint_ref": "ckpt-2231",
  "evidence_cost": { "units": 4200, "currency": "USD" },
  "runtime_assurance_tier": "attested",
  "evidence_class": "verified",
  "replay_recipe_sha256": "51d0...",
  "bond_ref": "bond-req-listing-01",
  "status_feed_ref": "finding-status/acme-lab",
  "issuer": "ed25519:6f...",
  "issued_at": 1784880000,
  "expires_at": 1792656000,
  "signature": "..."
}
```

Negative-result profile differences: `outcome_class: null_result`,
`guarantee_class` usually `metered_attested`, `replay_recipe_sha256` present
only when the experiment is re-runnable, and the descriptor topic is an
experiment-space coordinate rather than a repo key.

### 4.2 Delivery receipt metadata (two blocks, two milestones)

Review finding: the kernel must not attach fields it cannot source from
verified inputs. `OutputDigestSha256` carries only the digest, so at M3
the kernel can truthfully attest exactly that - the finding-specific
context arrives at M4, when the bid-mint extension gives it a SIGNED
carrier. Two blocks, following the typed-metadata-block pattern
(`governed_transaction`, `economic_authorization`;
`spec/PROTOCOL.md:906-988`):

**M3, generic: `chio.delivery-contract.v1`** - sourced entirely from
inputs the kernel itself validated: `expected_output_sha256` (from the
token constraint) and `digest_check: matched` (its own comparison).
Nothing else; usable by any output-committed tool call, not only findings.

**M4, finding overlay: `chio.finding.delivery.v1`** - the fields below,
attached only when the purchase context arrives through verifiable
artifacts. The buyer presents BOTH the provider-signed
`SignedAskResponse` and the buyer-signed `AcceptedBid` via the
governed-intent context (review finding: `AcceptedBid` alone is
buyer-signed and carries only an opaque `ask_digest`, so without the ask
body the kernel can neither authenticate the provider nor bind the token
to that ask - a token subject could sign arbitrary purchase fields for
the kernel to echo). The kernel verifies FOUR presented artifacts, with the signed
`chio.finding.v1` as the ANCHOR that binds identity to commitment (review
findings: `SignedExportEnvelope::sign` is public, so prose calling a body
signed proves nothing until checked; and no ask/bid/pricing artifact
carries the `finding_id -> payload_sha256` link, so trusting them alone
lets a provider scope a pricing hint to finding B while minting the token
digest constraint for payload A - all signatures verify and the receipt
stamps B with A's digest). The checks:
(1) the signed `Finding` - its inline issuer signature (`verify_finding`),
and its `finding_id` recomputed as the content address (`verify_finding_id`);
(2) the delivery binding - `finding.payload_sha256` equals the token's
`OutputDigestSha256` constraint (the id-to-digest link is now
issuer-signed, not inferred);
(3) the ask - `SignedAskResponse` envelope signature against the token's
issuer key; token id/subject/expiry and `listing_id` against the token,
and the provider-signed `SignedListingPricingHint` (same signer as the
token issuer, `pricing.listing_id == ask.listing_id`) whose
`capability_scope = finding:<finding.finding_id>` matches the anchor's id;
(4) the accepted bid - `SignedAcceptedBid` envelope signature against the
token's SUBJECT key with `canonical_digest(ask.body) ==
accepted.ask_digest` and the `agent_id`, `listing_id`, `bid_digest`,
`quoted_price` cross-binding.
(5) the funds reservation - the `bid_receipt_id` inside the accepted bid
is buyer-supplied text (`SignedAcceptedBid::sign` is public and the buyer
owns the subject key), so it is NOT reservation-backed until checked
against real reservation state (review finding; this mirrors what the
shipped `accept()` does via `VerifiedReservationReceipt`). Single-operator
(the M4 wedge): the mediating kernel consults its OWN verified reservation
/ budget-hold state keyed by `bid_receipt_id` - authoritative, no presented
artifact needed. Cross-org (M7): the buyer additionally presents the
`SignedReservationReceipt`, and the kernel verifies its signature against
the settlement reservation authority and cross-binds `receipt_id ==
accepted.bid_receipt_id`, `ask_digest == accepted.ask_digest`, `agent_id`,
`listing_id`, and `reserved_amount >= quoted_price`.
Only after all five does the kernel stamp `finding_id` (from the anchor,
never from caller-controlled request arguments; two findings may legitimately
share one `payload_sha256`, 4.5, so the id must come from the signed
finding, not the digest). `accepted_bid_ref` is recorded as
reservation-backed only because (5) proved it. Failure handling is profile-dependent and fail-closed:
for a finding purchase (the grant was minted under a finding listing and
purchase context is expected), malformed or missing purchase artifacts
DENY the call - silent omission would let a caller downgrade out of the
finding-specific proof; omission of the overlay is legitimate only for
generic output-committed calls that never claimed a finding purchase.
Caller-asserted copies without those signed artifacts are never promoted
into this block (P10 discipline). The `status_proof` sub-block is NOT
part of M4: it is an optional, signature-safe addition completed at M6,
which breaks the former M4-to-M6 dependency cycle (M4 ships the overlay
without status fields; M6 adds them additively per the 7.3 evolution
rules):

| Field | Semantics |
|---|---|
| `finding_id`, `listing_id` | what was delivered |
| `expected_payload_sha256` | the commitment the delivery was checked against |
| `digest_check` | `matched` (the only value on an Allow; a mismatch never produces an Allow) |
| `purchase.bid_digest`, `purchase.ask_digest`, `purchase.accepted_bid_ref` | handshake binding |
| `status_proof.epoch_root_ref`, `status_proof.non_inclusion_checked_at` | (M6, optional-additive) the freshness evidence the buyer presented |

The Allow receipt for `read_finding` carrying these blocks, under the
`chio.mediated_spend.v1` conjunction (`receipt/authoritative_spend.rs`), is
the **reveal proof**: it is what escrow release consumes (F3/F6) and what
disputes anchor on (F4). Note `content_hash` on the receipt body already
equals the served bytes' digest by WYSIWYS construction
(`receipt/signing.rs:273`); `expected_payload_sha256` records what it was
required to equal. Per the C2 boundary above, this proves a
kernel-attested reveal, not buyer retention.

### 4.3 `chio.finding.challenge.v1` (schema registered at M5, its owning milestone)

| Field | Semantics |
|---|---|
| `challenge_id`, `finding_id`, `challenger` | identity |
| `challenge_class` | `digest_mismatch` / `evidence_invalid` / `replay_contradiction` (only mechanically decidable classes; D4) |
| `reproduction_receipt_ids`, `reproduction_checkpoint_ref` | for `replay_contradiction`: the challenger's mediated re-execution of the committed recipe |
| `replay_recipe_sha256` | must equal the finding's committed recipe digest |
| `challenge_bond_ref` | Dispute-class bond posted by the challenger (`fee_schedule.rs:14`) |
| `decision_rule_ref` | the predeclared rule id this challenge invokes (ADR-0015 follow-up B pattern, `crates/economy/chio-market/src/claim.rs:38-50`) |

Evaluation is a pure fail-closed function (repo idiom:
`evaluate_open_market_penalty`, `crates/economy/chio-open-market/src/evaluation.rs:79`):
verify signatures; verify the reproduction receipts exactly as claim evidence
is verified today (`insurance_flow.rs:390-414`); compare verdicts under the
committed recipe predicate; emit a finding-code result that either feeds a
governance Sanction case (slash path) or dies. No new adjudication authority
is created; non-mechanical disputes stay out of scope of this artifact.

### 4.4 Status feed

The feed is a second deployment of the existing sparse-Merkle revocation
oracle keyed by finding id
(`RevocationKey { subject_id, epoch_nonce }` generalizes;
`crates/trust/chio-revocation-oracle/src/api.rs:70`), with signed
`EpochRoot`s, inclusion proofs (retracted) and non-inclusion proofs (still
good), freshness windows, and optional anchoring of roots through the
existing anchor lanes. Retraction inserts come from: the seller (voluntary),
or an enforced challenge outcome (F4). The feed artifact
(`chio.finding.status-epoch.v1`, registered at M6, its owning milestone)
MUST contain or reference the oracle's exact
`SignedEpochRoot { root: EpochRoot, signature: RootSignature }`
(`chio-revocation-oracle/src/epoch.rs:12`, `api.rs:86-98`) plus feed
identity and anchoring refs - never a partial copy of the root. Two
precision points from review: (1) the oracle key is
`RevocationKey { subject_id, epoch_nonce }`, so the feed contract pins a
FIXED domain nonce (`epoch_nonce = "chio.finding.status.v1"`) and every
insert and proof uses exactly `(finding_id, that nonce)` - otherwise a
retraction under one nonce coexists with fresh non-inclusion proofs
under another. (2) Signed-ROOT verification carries over unchanged, but
today's `NonInclusionProof { key, epoch_root, checked_at }` carries no
path bytes and `verify_non_inclusion` consults the verifier's LOCAL
oracle state (`api.rs:110-114`, `sparse_merkle.rs:77-79`) - it is not a
portable absence proof. M6 therefore either extends the oracle with
portable sparse-Merkle non-inclusion paths verifiable against the signed
root (the required default), or explicitly documents the proof endpoint
as a trusted-query surface backed by the operator bond - it must not
label the online answer a proof.

### 4.5 The reveal envelope and the exact digest definition (normative)

A fine detail that decides whether the delivery contract works at all: the
kernel's `content_hash` for a value output is
`sha256_hex(canonical_json_bytes(value))` over the WHOLE response value
(`receipt_content_for_output`,
`crates/kernel/chio-kernel/src/receipt_support/receipt_content.rs:3-17`).
The seller's commitment must therefore be over exactly that quantity, not
over raw payload bytes. Normative definitions for the family:

- The `read_finding` response value MUST be exactly the reveal envelope
  (snake_case keys; canonical JSON key ordering makes it deterministic):

```json
{
  "media_type": "text/x-diff",
  "payload_b64": "<base64 of the raw payload bytes>"
}
```

- `Finding.payload_sha256 := sha256_hex(canonical_json_bytes(reveal_envelope))`.
  It is the digest of the canonical envelope, NOT of the decoded payload
  bytes. Buyers recover raw bytes by base64-decoding `payload_b64` after
  independently recomputing the envelope digest.
- The envelope's `media_type` MUST equal the signed artifact's
  `payload_media_type` (review finding: the digest gate only checks the
  envelope hash, so without this rule a seller could advertise
  `text/x-diff` while committing to some other type, and a buyer that
  auto-applies on the advertised type is misled). It is buyer-checkable on
  the revealed bytes and a mismatch is a challengeable delivery failure
  (the `evidence_invalid` class): the reveal server MUST set
  `envelope.media_type == finding.payload_media_type`, and the buyer
  rejects the reveal if it does not.
- The envelope deliberately EXCLUDES `finding_id`. Including it would
  create a hash cycle: `finding_id` is content-addressed over the artifact
  body, which contains `payload_sha256`, so an envelope containing
  `finding_id` would make each digest depend on the other and no artifact
  could be constructed deterministically. Nothing is lost by the
  exclusion: which finding was served is already bound three ways - the
  token constraint equals that finding's commitment, the receipt's
  `action.parameter_hash` covers the request arguments naming the finding,
  and the `chio.finding.delivery.v1` block records `finding_id`
  explicitly. Identical payload bytes across two findings yield the same
  envelope digest, which is semantically correct (identical bytes are the
  identical good).
- Streams are excluded in v1: a streamed output's `content_hash` is a
  concatenation of per-chunk digests, and stream retention caps can
  truncate it into an Incomplete receipt (`stream_receipt_content` and
  `truncate_stream_to_limits`, same file), so a grant carrying the
  delivery constraint MUST deny a `Stream` output fail-closed. Payload
  size is therefore bounded by response-value limits; large payloads ship
  as a small envelope containing a fetch reference plus the digest of the
  referenced bytes only if a later ADR defines that indirection (not v1).

## 5. Market flows

### F1. Publish and admit

0. (Optional, priced-in) Before running the work, the producer commits the
   experiment/protocol digest via a tiny mediated call; its receipt is the
   pre-outcome intent commitment later referenced as
   `intent_commitment_receipt_id` (4.1). Zero new machinery: any governed
   call binding the digest in its parameter hash works.
1. Producer agent finishes the work; its receipts and cost metadata already
   exist as a side effect of mediation.
2. Assemble `chio.finding.v1`: seal the payload (seller-side storage), digest
   it, reference the evidence receipts + checkpoint, commit the replay recipe
   (wedge), sign.
3. Publish a listing + signed pricing hint through the registry
   (`chio-listing` discovery shapes, `src/discovery.rs:48,203`).
4. Trust activation: the finding listing is admissible only `BondBacked`
   (`crates/economy/chio-listing/src/trust_activation.rs:565` keeps unbacked
   listings review-only); the bond requirement must be `slashable: true`
   (`fee_schedule.rs:56`).
5. Optional discovery hint: a pheromone deposit on the topic class pointing
   at the listing (free tier; `crates/trust/chio-pheromone/src/lib.rs:341`).

### F2. Discover and verify (buyer, pre-purchase, no payment yet)

1. Buyer hits the same failing context; computes `context_sha256`; searches
   listings by descriptor (prefix + digest equality;
   `chio-listing/src/discovery.rs:144,291`).
2. Offline verification of the finding: signature; evidence receipts verify
   fail-closed (signatures, checkpoint inclusion, revocation state) via the
   buyer boundary (`crates/trust/chio-attest-buyer/src/api.rs`); issuer
   consistency with evidence lineage (anti-plagiarism, threat model S5);
   guarantee-class claims within `ChioProofClaims` limits.
   Evidence-sharing modes (the X2 side-channel trade-off made explicit):
   pre-purchase verification needs receipt bytes, and full receipts carry
   exact `cost_charged` in their financial metadata, re-leaking what a
   bucketed `evidence_cost` hides. Sellers therefore choose per listing:
   (A) full-receipt evidence - everything verifiable pre-purchase, exact
   cost profile leaks; the wedge default for org-internal contexts; or
   (B) projected evidence - BBS-projected receipts revealing only the
   slots verification needs while hiding the `metadata` slot
   (`chio-selective-disclosure` 14-slot projection), so cost claims
   verify only at audit or post-purchase. Correspondingly,
   `evidence_cost` granularity in the artifact is seller-chosen
   (bucketing is legitimate); no validator requires it to equal the
   receipt sum pre-purchase, and a wildly false rollup is
   `evidence_invalid` challenge material once receipts are examined.
3. Fresh non-inclusion proof from the status feed inside the freshness
   window (`api.rs:116`).
4. Elicitation ceiling computed (MECHANISMS section 2); if posted price is
   above the ceiling, walk away (no negotiation in v1).

### F3. Purchase and reveal (single-operator / wedge path)

1. `BidRequest` with ceiling against the finding listing
   (`bidding.rs:101`); provider `AskResponse` mints the `read_finding`
   capability: `max_invocations: 1`, `max_total_cost: price`, expiry, and
   the delivery binding (expected digest) attached per section 6. Fine
   print: `bid()` currently mints the grant with `constraints:
   Vec::new()` hardcoded (`bidding.rs:396`), so the flow needs a small
   open-market extension - provider-supplied grant constraints on
   `BidMintContext` - before the seller can inject
   `OutputDigestSha256(finding.payload_sha256)` at mint time. The buyer's
   accept-time check (token constraint equals the finding's commitment)
   is what makes the injection trustworthy.
2. `accept()` against the kernel funds-reservation receipt
   (`bidding.rs:439`, `AcceptedBid.bid_receipt_id`).
3. Buyer invokes `read_finding` through the kernel: capability verify ->
   MustPrepay hold funded from the quoted price -> guards -> dispatch to the
   seller's finding server -> **digest gate** (section 6) -> Allow receipt
   with `chio.finding.delivery.v1` block; reconcile settles exposed to
   realized (`kernel/reconciliation.rs:135`).
4. Failure paths, all existing: digest mismatch or guard deny -> signed
   Deny/Incomplete receipt + budget reversal
   (`kernel/validation.rs:1102`); seller unreachable -> hold released or
   reaped; abort after prepay -> refund (`kernel/dispatch.rs:170`).
5. Buyer ingests via a governed memory write; provenance chain binds
   store/key to the purchase capability and delivery receipt
   (`memory_provenance.rs:63`).
6. Paid-but-lost-payload edge (fine detail, M4): with `max_invocations: 1`,
   a buyer that crashes between the Allow receipt and persisting the
   payload has paid for bytes it no longer holds. Correction (review
   finding): the `Operation::ReadResult`-on-the-grant option does NOT
   work today - `grant_matches_request` matches only grants containing
   `Operation::Invoke` (`request_matching.rs:337-347`) and there is no
   kernel `ReadResult` request path, so such a grant authorizes no
   re-read. The M4 DEFAULT is therefore the seller re-serve policy keyed
   on presentation of the delivery receipt (no kernel change: the buyer
   re-invokes `read_finding` and the seller server, seeing a valid
   delivery receipt for that finding, serves the same bytes; the digest
   gate still binds them). A kernel-native receipt-keyed read-result
   matcher is the alternative and is a real kernel change, deferred. The
   failure mode remains buyer-loses-availability, never
   seller-double-paid.

### F4. Challenge, audit, and slash

1. Challenger (any bonded agent; typically a burned buyer, or the venue's
   audit scheduler - MECHANISMS section 5 requires published-rate random
   audits of listed findings, funded from participation fees, because
   buyer-initiated challenges alone cannot deter fabrication of rarely
   re-checked claims) re-runs the committed replay recipe under mediation,
   producing reproduction receipts.
2. Assembles `chio.finding.challenge.v1` with the Dispute-class bond.
3. Pure evaluator checks it (4.3). `digest_mismatch` cannot occur for a
   delivered finding (structurally prevented) but covers advertised-payload
   fraud pre-delivery; `evidence_invalid` and `replay_contradiction` are the
   live classes.
4. A passing challenge feeds a governance case: Sanction, enforced
   (`chio-governance/src/generic.rs:17`); penalty `SlashBond` through the
   existing gate (`chio-open-market/src/evaluation.rs:356-451`); on-chain
   impairment with exact-sum distribution to harmed parties
   (`chio-settle/src/evm/prepare.rs:989-1020`); appeal path intact
   (`ReverseSlash`).
5. The enforced outcome also inserts the finding into the status feed
   (F5) - retraction and slash are one transition.

### F5. Retract and propagate

1. Insert finding id into the status oracle; new signed epoch root; anchor
   on cadence.
2. Buyers' subscription (or next purchase attempt) observes the root;
   holders of the finding get: the quarantine guard rule (opt-in) flips
   reads of memory keys whose provenance traces to the retracted finding
   from annotate to deny (`memory_governance.rs` extension; memo 6.5).
3. Blast radius per buyer via reverse lineage from the delivery receipt
   (`chio-lineage/src/query.rs:56`). Automatic invalidation of derived data
   stays out of scope (threat model A5 boundary).
4. Refunds on retraction are a POLICY choice recorded in the listing terms,
   not a protocol mechanism: if offered, they ride the existing
   claim/settlement lane, never a discretionary re-route (ADR-0015).

### F6. Cross-org purchase (escrow path)

Same as F3 with: funds in `ChioEscrow` (beneficiary = seller, deadline)
instead of only a kernel hold; release gated on Merkle-proven inclusion of
the delivery receipt under the operator-signed root
(`releaseWithProofDetailed`; batch `prepare_merkle_release`,
`chio-settle/src/lib.rs:40-91`); refund after deadline if no delivery.
Timing fine print: the delivery receipt becomes escrow-releasable only
after it lands in a signed checkpoint (and, per relying-party policy, an
anchored one), so the escrow `deadline` must exceed delivery time plus
checkpoint cadence plus anchor finality; a deadline tighter than the
operator's checkpoint interval can refund a completed delivery. The escrow
terms should therefore be derived from the operator's published checkpoint
cadence, not chosen freely.
Evidence and passport exchange ride the bilateral evidence-share surfaces
(`chio evidence export/import`, federation policy artifacts). The
operator-visibility caveat (threat model O1/T1) applies; TEE-tier kernels
are the mitigation. Transport-level federation is bounded to what ships
(ADR-0014 defers the mesh transport to Year-2).

**Whose operator key the escrow trusts (review finding; this was
unspecified and one choice falsifies a threat-model claim):**
`ChioEscrow` releases against the operator named in `EscrowTerms`, so the
choice of operator IS the fair-exchange design:

- One topology is allowed in the v1 escrow profile (review finding: an
  earlier bullet said "seller-side operator" while the consequence below
  disallows seller-aligned mediation; this states it once): the finding
  server MUST be registered with the NEUTRAL / MUTUALLY TRUSTED mediating
  kernel whose operator is named in `EscrowTerms`. Seller-side mediation
  is the explicitly disallowed case (attest-and-withhold, below).
  Naming a NON-mediating operator (e.g. buyer-side while the seller
  mediates) is also disallowed: it could observe nothing yet withhold the
  checkpoint until the refund deadline - refund-while-holding-payload.
- A mediating operator aligned with the seller creates the converse risk,
  in two layers. First, the minted token is bearer-shaped, so seller plus
  seller-side kernel could replay it with no buyer involved; escrowed
  purchases therefore MUST mint `dpop_required: true` grants (ADR-0007),
  making the delivery receipt prove a buyer-INITIATED reveal. Second -
  and DPoP does not close this (review finding) - the same mediator can
  accept a genuine buyer request, invoke the server, sign and checkpoint
  the Allow, SUPPRESS the response to the buyer, and still release
  escrow: attest-and-withhold. An Allow proves kernel-attested reveal
  (6.2), never response delivery.
- With both rules, withholding the checkpoint only hurts the withholder:
  an unpublished delivery receipt means no release before the deadline,
  refunding the buyer while the seller side already served the bytes.
  Deadlines must still exceed the operator's published checkpoint cadence
  plus anchor finality (timing fine print above).
- Consequence (review correction): the v1 cross-org ESCROW profile
  REQUIRES a mutually trusted or neutral mediating operator - that
  operator IS the trusted third party fair exchange provably needs
  (MECHANISMS 8.1). With a seller-aligned mediator, paid non-delivery via
  attest-and-withhold remains open, the residual is HIGH, and the flow
  must not be described as fair exchange; the profile is disallowed
  rather than shipped unfair. Buyer-acknowledgment alternatives
  (capture-after-ack, durable re-read before release) invert the theft
  direction (buyer withholds the ack while keeping the payload) and are
  admissible only with a predeclared ack-vs-refund adjudication rule -
  an M7 design decision, not assumed here. M7 exit therefore carries the
  operator-model decision plus BOTH adversarial tests: withhold-root and
  withhold-response.

## 6. Kernel enforcement points (delivery contract)

The digest gate is the one genuinely new enforcement obligation:
**no Allow receipt for `read_finding` unless the served bytes hash to the
committed `payload_sha256`.** The kernel internals dictate the shape; three
facts from the evaluation pipeline decide it.

### 6.1 The facts that constrain the design

Scope note (added when PR #974 surfaced): these facts were verified
against pre-#974 main. PR #974 rewrites large parts of `validation.rs`,
`budget_store.rs`, and the response builders, adds an explicit
invocation-capture stage and a pending-approval response kind, and
replaces `unwind_aborted_monetary_invocation` with the capture lifecycle
(`reverse_pre_execution_budget_mutation` survives). The three facts below
held at verification time and the design DIRECTION does not depend on the
line numbers, but every anchor here must be re-verified against post-#974
main before the M3 plan is authored (PLAN section 0).

- **F-A. The paid path skips post-invocation hooks.** The post-invocation
  pipeline (`PostInvocationHook`, `crates/kernel/chio-kernel/src/post_invocation.rs:56`)
  runs only from `finalize_tool_output_with_metadata`, which the budgeted
  finalizer invokes only when there is no charge
  (`kernel/validation.rs:1275,1320`); a monetary invocation (which a paid
  reveal always is) bypasses hooks entirely, and a hook `Block` cannot claw
  back a charge anyway (no reversal on the post-dispatch success path).
  Hooks are therefore NOT a viable home for the gate.
- **F-B. Constraints are input-side.** `constraint_matches` has no
  tool-output parameter (`chio-kernel/src/request_matching.rs:371`); every
  existing `Constraint` variant evaluates against request
  arguments/metadata. A constraint alone cannot compare an output hash.
- **F-C. The one common surface that computes the served-output digest is
  the receipt-content builder.** `receipt_content_for_output`
  (`receipt_support/receipt_content.rs:3`,
  `sha256_hex(canonical_json_bytes(value))`) feeds
  `build_allow_response_with_metadata` (`kernel/responses/allow_responses.rs:49`),
  common to monetary and non-monetary allows - but on the monetary path
  `reconcile_budget_charge` runs BEFORE that builder
  (`kernel/validation.rs:1422`), so a check there would deny after
  settlement, losing clawback.

### 6.2 Chosen design

**Carrier: a new `Constraint::OutputDigestSha256(String)` variant, minted by
the SELLER into the `read_finding` grant of the `AskResponse.token_offer`.**
Rationale: the committing party must be the seller (the digest is the
seller's commitment, so a buyer-supplied carrier like
`governed_intent.context` is the wrong trust direction); the constraint
mechanism is the established per-grant extension point (recent precedent:
`MemoryStoreAllowlist`, `MemoryWriteDenyPatterns`,
`crates/core/chio-core-types/src/capability/scope.rs:284`); and the buyer
verifies at accept time that the token's constraint equals the finding's
`payload_sha256` (a pure equality check, no kernel involvement). Wire
compatibility is fail-closed in the right direction: the enum has no
`serde(other)` fallback, so an old kernel hard-rejects a token carrying the
new variant - an unenforceable delivery refuses to parse rather than
running unprotected.

Why not the existing `Constraint::Custom(String, String)` (the obvious
no-new-variant alternative): `Custom` is evaluated input-side as an
argument-containment check
(`Constraint::Custom(key, expected) => Ok(argument_contains_custom(...))`,
`chio-kernel/src/request_matching.rs:420`) - it never sees the output, and
an old kernel would parse a Custom-carrying token and dispatch WITHOUT any
digest gate. For a payment-bearing delivery contract that is fail-OPEN
across version skew, the one failure direction this design refuses. A
capability `.v2` schema is the heavyweight fallback if the v1 constraint
vocabulary is declared frozen at M3 time; the formal call is ADR-A
(PLAN section 4), and the addition ships with its PROTOCOL.md update and
verdict-matrix rotation either way. Precedent since this was written:
PR #974 itself adds `Constraint::RequireCumulativeApprovalAbove` in
place, so in-v1 vocabulary extension is the repo's demonstrated practice,
not a novelty this program introduces.

**Enforcement point: two layers, so the invariant holds on EVERY Allow
path, not only the charged branch.** Review finding: `charge_result ==
None` (including MustPrepay without a grant monetary ceiling) returns
through `finalize_tool_output_with_metadata`, and the unmeasured-cost path
emits a provisional Allow through
`finalize_unmeasured_cost_provisional_allow` (`validation.rs:1202`) -
a charged-branch-only check would let those paths Allow unverified.

- **Layer 1 (universal, soundness):** the check lives in
  `build_allow_response_with_metadata`
  (`kernel/responses/allow_responses.rs:49`), the single choke point every
  Allow arm routes through (plain, charged, MustPrepay-settled, and
  provisional alike). It already holds the request capability and the
  computed receipt content; a digest mismatch or a `Stream` output under
  the constraint routes to the deny builder instead. No Allow can be
  emitted that violates the constraint, on any path.
- **Layer 2 (money-correctness, BEFORE every irreversible settlement):**
  Layer 1 keeps soundness but on some branches it would deny AFTER the
  money already moved, losing the refund handle. The gate must therefore
  also run before each settlement/capture point (review finding: the
  no-ceiling MustPrepay branch was the missed one):
  - charged branch: before `reconcile_budget_charge`
    (`kernel/validation.rs:1422`); on mismatch reverse the charge.
  - no-ceiling MustPrepay branch (`charge_result == None` with a payment
    authorization present): before
    `settle_prepaid_authorization_without_charge`
    (`validation.rs:~1290`, which runs before
    `finalize_tool_output_with_metadata`); on mismatch RELEASE the
    authorization (refund) rather than capture. Without a pre-settlement
    gate here the prepaid quote is already captured by the time Layer 1
    denies, and there is no authorization handle left to refund.
  Both are the same rule - gate before the irreversible money move on that
  branch - and Layer 1 is the backstop for genuinely-unpaid paths.

M3 must test each former bypass explicitly WITH its refund: charged
(hold reversed), no-ceiling MustPrepay (authorization released, not
captured), unmeasured provisional, and stream outputs. When the matched grant carries `OutputDigestSha256(expected)`:

- A `Stream` output is an immediate mismatch (4.5): deny fail-closed.
- For a `Value` output, compute the digest with the same
  `receipt_content_for_output` canonicalization and compare to `expected`.
- On mismatch: reverse the charge and emit a signed Deny receipt. This has
  in-function precedent, which is why the placement is feasible rather
  than invasive: the finalizer ALREADY reverses a pre-execution hold after
  dispatch on its no-measured-cost path ("Reverse the pre-execution hold
  and emit a provisional receipt", the guard block above
  `finalize_unmeasured_cost_provisional_allow`, `validation.rs:1333-1349`),
  using the `reverse_pre_execution_budget_mutation` family
  (`validation.rs:1102`). The mismatch arm must ALSO release or refund any
  payment authorization (MustPrepay), mirroring
  `unwind_aborted_monetary_invocation` (`kernel/dispatch.rs:170`) - a
  mismatch after prepayment is economically an abort.
- On match: proceed to reconcile and attach the generic
  `chio.delivery-contract.v1` block (4.2) in the allow builder; the
  finding overlay is attached at M4 when its signed purchase context is
  presented.

At the input-matching site the new variant is an advisory pass (precedent:
the data-layer variants return `Ok(true)` pre-dispatch,
`request_matching.rs:428`). Redaction interaction: post-invocation
transforms do not run on the charged path (F-A), so nothing rewrites the
delivered value between the gate and `content_hash` today; if hooks are
ever enabled on charged paths, the gate must move to compare the
post-transform value or the two hashes diverge.

Invariant this creates (formalization candidate, see PLAN):
**kernel-attested reveal soundness** - for any grant carrying
`OutputDigestSha256(d)`, an Allow receipt implies the kernel accepted an
output preimage with `content_hash == d` (WYSIWYS composition,
`receipt/signing.rs:273`). Stated deliberately inside the kernel
observation boundary: an Allow does NOT prove the buyer process received
or durably retained the bytes (the crash window in F3 step 6), and
payment capture follows the Allow. If the intended product claim is ever
buyer delivery rather than kernel-attested reveal, the protocol must add
durable re-read or capture-after-buyer-ack first - that choice is the M4
delivery-idempotency decision, and until it lands the buyer bears
post-Allow availability risk.

### 6.3 Facts that simplify the rest

- **Seller servers are dumb and buyer-blind.** `ToolServerConnection::invoke`
  receives only `(tool_name, arguments, nested_flow_bridge)`
  (`chio-kernel/src/runtime.rs:342`) - no buyer subject. The capability is
  the entire access control; the server just serves the sealed bytes for
  the finding id in `arguments`. Per-buyer payload discrimination is
  structurally hard, which is anti-fraud by accident and by design.
- **The kernel ignores manifests.** Registration is
  `register_tool_server(Box<dyn ToolServerConnection>)`
  (`kernel/construction.rs:1462`); `chio-manifest` is an edge/platform
  concern. The finding server needs no manifest change; the signed manifest
  (with `ToolDefinition.output_schema`, no digest field -
  `chio-manifest/src/lib.rs:120`) stays advisory listing metadata.
- **api-protect cannot host the seller side as built**: its receipts bind
  the request digest and response status, never a response-body hash
  (`chio-api-protect/src/proxy/router.rs:211,356-372`,
  `chio-http-core/src/request.rs:119`). Either sellers run a native tool
  server (v1 answer) or api-protect grows response-hash binding (deferred;
  decision backlog).

## 7. Artifact governance and schema evolution

### 7.1 Registration obligations (per new schema id)

Every schema in section 4's table must land in four places, cross-checked by
test (`crates/core/chio-core-types/tests/signed_artifact_schema.rs` asserts
code and registry agree):

1. A JSON validation schema under `spec/schemas/chio-finding/v1/*.schema.json`
   (validated by `chio-spec-validate`; note the family types are
   hand-written Rust - only the `chio-wire` transport types are codegen'd
   from JSON schema via `chio-spec-codegen`).
2. A row in `spec/schemas/registry.json` (`{schema, artifactKind,
   introducedBy, schemaFile}`) plus `spec/schemas/MANIFEST.sha256`.
3. A `CHIO_FINDING_*_SCHEMA` const and a `SIGNED_ARTIFACT_SCHEMA_SPECS` row
   in `crates/core/chio-core-types/src/signed_artifact.rs` (the fail-closed
   accept-list: unknown schemas are rejected at load and at
   signature-verification time, per the normative registry section,
   `spec/PROTOCOL.md` "Signed-Artifact Registry").
4. A PROTOCOL.md section under 6.4.x describing the family.

### 7.2 Family layout and proof-bundle binding

Template = the commerce-order family
(`crates/platform/chio-commerce-order`: schema ids in `src/ids.rs`, types
`deny_unknown_fields` in `src/types.rs`, per-concern validators, one
top-level `verify_*` in `src/lib.rs:47`, goldens under
`fixtures/proof-room/<family>/<case>/`). The finding family follows it in
the new `chio-finding` crate with goldens at `fixtures/proof-room/finding/`.

Transaction-passport binding adds NO new evidence-graph role - the role set
is closed (8 variants, fail-closed custom deserialize,
`chio-transaction-passport/src/evidence_graph.rs:36,105`). The finding
verifier binds through the existing `ClaimSet` role by emitting claim ids,
proposed: `claim.finding.delivery_digest_bound`,
`claim.finding.evidence_bound`, `claim.finding.status_fresh`,
`claim.finding.bond_backed` - each carried as a claim-set entry naming the
verifier module and evidence refs (delivery receipt, checkpoint, oracle
non-inclusion proof, bond artifact), with digest pins for `payload_sha256`
and the evidence artifacts.

### 7.3 Schema-evolution posture (and the listing decision)

The repo's rules, now confirmed: verifier-input artifacts are
`deny_unknown_fields` fail-closed; additive changes are `Option` +
`#[serde(default, skip_serializing_if)]` ("signature-safe": omitted-when-
absent keeps existing signed fixtures byte-stable - exemplar:
`decision_rule_ref` on `LiabilityClaimAdjudicationArtifact`,
`crates/economy/chio-market/src/claim.rs:305`); **adding an enum variant to
a frozen wire enum is BREAKING** (no `non_exhaustive`, no `serde(other)`;
the sanctioned route is a new `.v2` schema).

Consequently the listing integration does NOT extend
`GenericListingActorKind` (closed 4-variant enum,
`chio-listing/src/listing.rs:23`). Chosen shape, zero listing changes:

- The listed subject is the seller's finding server under the EXISTING
  `ToolServer` actor kind (which is literally true - the subject serves
  `read_finding`), with `GenericListingSubject.metadata_url` /
  `resolution_url` pointing at the `chio.finding.v1` artifact
  (`listing.rs:199`).
- The good's identity rides the pricing hint's `capability_scope` and the
  finding artifact itself; the bid flow consumes the listing unchanged.
  Scope strings follow the marketplace's actual colon-segment semantics
  (`capability_scope_covers` splits on `:` and requires the advertised
  scope to be a segment-prefix of the requested one,
  `chio-open-market/src/bidding.rs:534`), so the convention is
  `finding:<finding_id>` advertised and requested exactly - verified
  end-to-end through the real `bid()` path by
  `finding_purchase_clears_the_real_bid_path` in the spec test.
- Descriptor search (by `context_sha256`) is a finding-index service
  surface (8.1), not a listing-schema change.

This revises ADR-0017 D1's "new subject kind" phrasing; the ADR gets a
one-line amendment rather than the wire a breaking change (PLAN, M0).

One admission seam is real and must be built: `BondBacked` listings never
auto-admit today - `require_bond_backing` pushes `BondBackingRequired` and
returns `admitted = false` ("review-visible only until bond backing is
proven", `chio-listing/src/trust_activation.rs:558-572`). The finding
market needs the bond-proof gate that clears this (a signed bond artifact
check against the fee schedule's requirement), which is generic
open-market work, not finding-specific.

### 7.4 Conformance obligations

Two layers (different costs):

- **Family goldens** (cheap): `fixtures/proof-room/finding/<case>/` +
  `chio-finding/tests/` mirroring `commerce_order.rs:22`, plus
  schema-validation of goldens.
- **Verdict-matrix corpus rotation** (expensive, gated): the digest gate
  changes tool-access verdicts, so it needs new scenarios in
  `crates/tooling/chio-conformance/verdict_matrix/scenarios/` (a new
  `delivery_contract` class), recomputed `scenario_index_hash` +
  `corpus_sha256` in `manifest.toml`, an update to
  `docs/conformance/verdict-matrix.md`, and all required drivers
  re-emitting the tuples. This lands with the kernel change (PLAN M3), not
  before.

### 7.5 Receipt-metadata block registration

Both blocks follow the typed-block pattern: structs in
`crates/core/chio-core-types/src/receipt/` (fields additive per 7.3),
kernel inserts under the string keys `"delivery_contract"` (M3, generic)
and `"finding_delivery"` (M4, overlay) (insertion sites pattern:
`receipt_support/receipt_metadata.rs:433,543`), read via the generic
`typed_metadata::<T>(key)` accessor (`receipt/body.rs:563`).
There is no central metadata-key registry today (only the signing nonce key
is formally reserved, `receipt/signing.rs:106`); we add a named const
beside it and document the key in PROTOCOL.md 6.4 - and PLAN flags the
missing registry as a repo-wide hygiene item worth fixing while we are
there.

## 8. Services and deployment

### 8.1 Trust-control surfaces (control plane)

`chio trust serve` is one axum router
(`chio-control-plane/src/service_runtime/router.rs::build_router`), and the
add-a-surface pattern is three steps: path const in
`service_types/paths.rs`, route in `router.rs`, handler in
`trust_control/*_handlers.rs` with request/response types and storage in
`service_runtime/`. Relevant surfaces already hosted: public listing search
(`/v1/public/registry/listings/search`, `paths.rs:42`), passport status +
challenge state, budget-store remote, and a flat capability-revocation list
(`/v1/revocations` - NOT the sparse-Merkle oracle).

New surfaces (wedge scope, all following the same pattern):

- `POST/GET /v1/findings/search` - descriptor index (topic prefix +
  `context_sha256` equality) over published finding artifacts; precedent:
  the generic-listing search handler (`certification_handlers.rs:143`).
- `GET /v1/findings/status/{feed}/root` and
  `GET /v1/findings/status/{feed}/proof/{finding_id}` - epoch root and
  (non-)inclusion proofs from the finding-status oracle instance. The
  oracle core is domain-generic already (`RevocationKey{ subject_id,
  epoch_nonce }`, `SubjectId(String)`,
  `chio-revocation-oracle/src/api.rs:28,70`); a fresh instance keyed by
  finding id needs NO new oracle types. HTTP is the pragmatic wedge
  transport; the federation gossip/iroh lanes
  (`chio-federation/src/revocation_gossip.rs`,
  `chio-federation-transport-iroh/src/lanes/revocation.rs`) are the
  cross-org distribution path later.
- Challenge submission rides the existing open-market penalty surfaces
  (`OPEN_MARKET_*` routes) once the abuse class exists.

### 8.2 The scheduling gap (explicit)

There is NO in-repo job runtime: `AnchorAutomationJob` and the settle
watchdogs are cron-descriptor artifacts with `assess_*` verifiers, and
nothing in the workspace schedules them
(`chio-anchor/src/automation.rs:37`, `chio-settle/src/automation.rs:36`; no
scheduler dependency exists). Status-feed epoch ticking
(`tick_and_broadcast`, `chio-revocation-oracle/src/epoch.rs:116`) and
root anchoring therefore run under operator cron per runbook, exactly like
anchoring does today. PLAN carries this as a documented operational
dependency, not new daemon engineering.

### 8.3 CLI surface

New `Commands::Finding` family following the documented pattern (clap enum
in `cli/types/`, dispatch module registered in `cli/dispatch/mod.rs:1-60`,
`cmd_*` fns calling the control-plane client - end-to-end precedent:
`chio trust liability-market` from `cli/types/trust.rs:1099` through
`cli/dispatch/trust.rs:897` to `cli/trust/liability.rs:178`):

`chio finding publish` (F1), `search` (F2), `verify` (offline evidence
verification via `chio-attest-buyer`), `buy` (F3 handshake + reveal),
`challenge` (F4), `status` (F5 proof fetch).

### 8.4 Release-process obligations (ship-dark first)

The bounded-release machinery gives the wedge a dark-ship path: a Rust
feature gate keeps the surfaces out of the bounded operational profile
until qualified, then entries land in the bounded qualification matrix
(`cargo xtask qualify bounded-chio`,
`docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json`;
`docs/release/QUALIFICATION.md:36`). Before any release-facing claim:

- CLAIM_REGISTRY rows: approved claims for the market wording plus
  `audited_assumption` rows for the two new trusted roles (finding-status
  oracle operator; seller tool server) - `docs/reference/CLAIM_REGISTRY.md`.
- RELEASE_CANDIDATE Supported-Guarantee or Explicit-Non-Goal entries.
- A `docs/release/CHIO_FINDING_MARKET_RUNBOOK.md` for the hosted surfaces
  (status feed cadence, challenge operations) per the service-runbook
  pattern.
- Conformance evidence in the qualification Evidence Matrix (7.4).
- ADR-0017 promoted Proposed -> Accepted (with the 7.3 amendment).

Retained non-claims stay retained: no consensus-HA, no distributed
linearizable budget, no public transparency log - the market design uses
none of them.

## 9. Crate-level integration map

| Crate | Change class | What |
|---|---|---|
| `crates/economy/chio-finding` (NEW) | new leaf crate | artifact types + pure validators for 4.1-4.4 shapes; no storage, mirrors `chio-listing` style |
| `crates/economy/chio-listing` | extend | finding listing integration per 7.3; descriptor search |
| `crates/economy/chio-open-market` | extend | `FabricatedFindingEvidence` abuse class; challenge evaluation module; evidence kinds |
| `crates/core/chio-core-types` | extend (additive) | `chio.delivery-contract.v1` (M3) and `chio.finding.delivery.v1` (M4) receipt metadata structs; delivery-binding carrier per section 6; schema registry entries |
| `crates/kernel/chio-kernel` | extend | digest-gate enforcement at the point chosen in section 6; delivery metadata attachment |
| `crates/guards/chio-guards` | extend | quarantine-on-retraction rule in `MemoryGovernanceGuard`; digest guard if option (a)/(b) in section 6 |
| `crates/trust/chio-revocation-oracle` | reuse | second instance for the status feed; feed-id envelope |
| `crates/platform/chio-control-plane` | extend | status-feed + finding search service surfaces per 8.1 |
| `crates/products/chio-cli` | extend | `chio finding publish/search/verify/buy/challenge/status` per 8.3 |
| `crates/economy/chio-settle` | extend (thin) | delivery-receipt-driven escrow release preparation (F6) |
| `crates/trust/chio-attest-buyer` | extend (thin) | finding evidence-bundle verification profile |
| `crates/tooling/chio-conformance` | extend | scenarios per 7.2/PLAN |
| `spec/PROTOCOL.md` | extend | finding family section under 6.4.x; explicit-gaps update |

## 10. Instance profiles

| Dimension | Wedge: verified fixes | Vision: R&D negative results |
|---|---|---|
| `outcome_class` | `verified_fix` | `null_result` |
| Guarantee class | `deterministic_replay` (replay recipe mandatory) | mostly `metered_attested`; replay only when re-runnable |
| Challenge lane | fully mechanical (re-run suite) | `evidence_invalid` only; replication protocols are future work (open problem 2) |
| Buyer's ceiling input | metered quote for running the failing suite | quote for the experiment, if quotable; else planner prior dominates |
| Descriptor privacy | low sensitivity (org-internal contexts) | high (existence of a dead end is signal); coarse topics + leakage budgets |
| Trust span | one operator or bilateral | cross-org from day one; TEE-tier pressure (threat model O1) |
| Residual risk driver | challenge griefing tuning | honest-cost fabrication (S2) |
| New machinery needed beyond wedge | - | replication decision rules; richer descriptor taxonomy; cross-org status-feed governance |

## 11. Non-goals (restated)

No auction or order book; no PSI/zk-SNARK machinery; no new escrow contract;
no finding-content storage inside Chio; no autonomous adjudication beyond
replay-checkable rules; no permissionless federation semantics
(`spec/PROTOCOL.md` section 14 posture unchanged).
