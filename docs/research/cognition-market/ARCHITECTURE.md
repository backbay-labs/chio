# Cognition Market Architecture

- Status: research architecture merged through PR #1025. This execution
  branch implements only M0/M1: `chio.finding.v1`, its pure crate,
  registration, normative text, golden, and test-only market spec.
  Operational market surfaces remain proposed.
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
- **Metering is a mode-bound signal, not a spam theorem.** Authenticated,
  semantically bound receipts can support a cost facet. Collected publication
  fees and live collateral provide the enforceable admission floors; metered
  cost alone proves neither truth nor resistance to cheap unrelated work.
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
   +----------------------------+     (chio-open-market + chio-governance)       | reserved budget
                                |       - signed challenge outcome               v
 KERNEL(S) - the TCB            |       - sanction -> bond impair            read_finding call
   capability verify            |     escrow + rails (chio-settle,               |
   budget reservation           +---    ChioEscrow/ChioBondVault,            delivery receipt
   reveal-time rail hold
   guard pipeline                       x402/ACP adapters)                       |
   digest-gated delivery check                                               governed memory write
   receipt signing (content_hash)                                            (provenance chain)
```

Every value move targets an existing rail backend. The authoritative
budget/liability reservation before pure bid acceptance, and the reveal-time
authorize/capture orchestration, are proposed M4 work, not shipped behavior.
The principal new boxes are the finding artifact family, the finding tool
server contract, and the status backend.

## 4. Artifact data model

Schema ids in the program (registration path in section 7):

| Schema | Kind | New/reuse |
|---|---|---|
| `chio.finding.v1` | signed information-good artifact | implemented and registered at M0/M1 |
| `chio.finding.replay-recipe-input.v1` | strict canonical verifier input committed by `replay_recipe_sha256` | new at M2 |
| `chio.finding.market-terms.v1` | seller-signed decision rules, liability windows, audit eligibility, backing, and payout policy | new at M2 |
| `chio.finding.seller-authorization.v1` | Finding-issuer-signed authorization for the exact seller, listing, provider, and payment beneficiary | new at M2 |
| `chio.finding.challenge-verifier-profile.v1` | reusable governance-signed role keys, projection trust, runner/predicate allowlist, bounds, and resolver policy; must predate recipe/Finding | new at M2 |
| `chio.finding.verifier-report.v1` | verifier-authority-signed per-facet evidence report bound to one Finding, profile, trust snapshot, and evidence bundle | new at M2 |
| `chio.finding.bond-backing.v1` | authority-signed exclusive seller collateral allocation and exposure policy | new at M2 |
| `chio.finding.admission.v1` | venue-signed Finding/listing/hint/evidence/fee/backing admission bundle | new at M2 |
| `chio.delivery-contract.v1` | generic terminal-receipt metadata for a concrete output digest check (M3) | new |
| `chio.finding.delivery.v1` | finding overlay metadata block (M4 purchase binding; optional `status_proof` sub-block added at M6) | new |
| `chio.finding.purchase-context.v1` | bounded strict verifier input carrying the signed M4 purchase chain | new at M4 |
| `chio.finding.purchase-record.v1` | signed authoritative terminal purchase/rail state, realized spend, liability, delivery, and immutable destination record | new at M4 |
| `chio.finding.failed-delivery.v1` | signed payout-ineligible M4 mismatch terminal binding the accepted bid, hold release, and checkpointed Deny | new at M4 |
| `chio.finding.challenge.v1` | signed origin-and-class-gated buyer challenge or bondless venue-audit submission | new |
| `chio.finding.replay-observation.v1` | strict receipt-bound replay phase and verdict preimage | new at M5 |
| `chio.finding.challenge-outcome.v1` | signed finding-specific evaluation and exact evidence digests mapped to the existing penalty lane | new at M5 |
| `chio.finding.challenge-enforcement.v1` | final liability, purchase snapshot, allocation, vault, penalty, and sequence-independent semantic-effect authorization | new at M5 |
| `chio.finding.finalized-bond-snapshot.v1` | observer-signed finalized chain/vault/allocation state consumed by enforcement | new at M5 |
| `chio.finding.audit-epoch.v1` | signed pre-execution eligible snapshot, randomness commitment, selection rule, rate, budget, and authorization | new at M5 |
| `chio.finding.audit-report.v1` | signed post-execution seed reveal, selected set, attempt evidence, and outcomes linked to one audit epoch | new at M5 |
| `chio.registry.market-penalty.v1` | generic enforced penalty; Rust v1 type/enums reused unchanged with `fraudulent_listing` and one exact `external` outcome ref, but public strict schema registration is missing and lands at M5 | register existing v1 wire shape at M5 |
| `chio.finding.status-epoch.v1` | domain-separated signed sparse status-map root | new at M6 |
| `chio.finding.status-proof-input.v1` | strict tagged portable inclusion/non-inclusion verifier input carrying the signed status epoch | new at M6 |
| `chio.finding.settlement-profile.v1` | governance-signed M7 operator, token, bridge, deadline, terminal, and SLA policy | new at M7 |
| `chio.finding.mediator-backing.v1` | bond-authority-signed non-reusable M7 mediator allocation and liability horizon | new at M7 |
| `chio.finding.escrow-witness.v1` | settlement-authority attestation of exact funded/final escrow state | new at M7 |
| `chio.finding.settlement-release.v1` | settlement-authority receipt binding delivery inclusion to one escrow release | new at M7 |
| `chio.finding.pool-allocation.v1` | authority-signed M8 companion binding one exact unsigned pool digest, qualified-ledger domain, purchaser, currency, amount, nonce, and validity window | new at M8 |
| `chio.finding.rederivation-quote.v1` | optional signed producer estimate for an exact context/recipe and currency | not shipped at M8; future only if authenticated quotes ship |
| `chio.marketplace.bid-request.v1` etc. | purchase handshake | reuse unchanged (`crates/economy/chio-open-market/src/bidding.rs:33-42`) |

### 4.1 `chio.finding.v1`

Field table (the implemented Rust types and PROTOCOL 6.4.7 are normative;
all structs use `deny_unknown_fields`, canonical JSON, and strict
issuer-bound Ed25519 verification):

| Field | Type | Semantics |
|---|---|---|
| `schema` | string | `chio.finding.v1` |
| `finding_id` | string | content-addressed: sha256 of the canonical body with `finding_id` AND `signature` retained as empty JSON strings `""` (never omitted or null) - the single canonical id input, identical to `compute_finding_id` |
| `descriptor.topic` | string | prefix-searchable topic key (org- or repo-scoped) |
| `descriptor.context_sha256` | hex64 | digest of the full context object (committed test suite + commit, or experiment protocol); the match key |
| `descriptor.outcome_class` | enum | `null_result` / `verified_fix` / `positive_result` |
| `guarantee_class` | enum | `deterministic_replay` / `metered_attested` / `asserted` (truthful-to-backing; D3) |
| `payload_sha256` | hex64 | commitment to the reveal: digest of the canonical reveal ENVELOPE, not raw payload bytes (normative definition in 4.5) |
| `payload_media_type` | string | e.g. `application/json`, `text/x-diff` |
| `evidence_receipt_ids` | [string] | unique producing-receipt ids (must verify fail-closed) |
| `evidence_checkpoint_ref` | string | checkpoint containing the evidence receipts |
| `evidence_cost` | {units, currency} | issuer-declared production-cost rollup; M2 can establish only a semantically bound kernel-accounted floor in full-receipt mode or after audit. Projected mode remains a seller assertion (MECHANISMS 1) |
| `runtime_assurance_tier` | enum? | tier from appraisal if the producing runtime was attested; `basic`/`attested`/`verified`, with omission as the only encoding for no assurance |
| `evidence_class` | enum | `asserted` / `observed` / `verified` linkage class of claim-to-evidence |
| `replay_recipe_sha256` | hex64? | REQUIRED for `deterministic_replay`: digest of the strict canonical `chio.finding.replay-recipe-input.v1` verifier input. M2 publication requires the preimage to be retrievable and hash-valid; M5 challenges carry it inline and re-check the digest |
| `intent_commitment_receipt_id` | string? | receipt id of a pre-outcome intent commitment. M1 checks only non-empty syntax. It earns an uplift only after M2 resolves the receipt, proves it predates every producing receipt, and verifies its parameter hash over a cycle-free pre-run descriptor/protocol template. The final recipe must commit that template digest. Outcome-derived fields such as the final payload digest, producing receipts, selected outcome class, and claimed verdict are excluded from the pre-run template. This resists protocol hindsight for the published Finding but does not prove completeness: a seller can precommit many trials and publish only favorable ones |
| `bond_ref` | string | opaque collateral reference at M1; it is not a requirement id or verified backing. M2 resolves it through the signed exclusive allocation and canonical fee-schedule requirement digest described in F1 |
| `status_feed_ref` | string | oracle feed id where retraction state is published |
| `license_ref` | string? | out-of-protocol license terms digest (B2 in threat model) |
| `price_hint_ref` | string? | optional cycle-free pre-Finding pricing-policy reference. M2 requires it absent for the Finding-scoped `ListingPricingHint`, because that hint signs `finding:<finding_id>` and its envelope digest therefore cannot also participate in the Finding-id preimage. The venue admission binds the final Finding and hint instead |
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
  "issuer": "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
  "issued_at": 1784880000,
  "expires_at": 1792656000,
  "signature": "..."
}
```

Negative-result profile differences: `outcome_class: null_result`,
`guarantee_class` usually `metered_attested`, `replay_recipe_sha256` present
only when the experiment is re-runnable, and the descriptor topic is an
experiment-space coordinate rather than a repo key.

V1 has no hidden-predicate carrier. `descriptor.outcome_class` is public and
the current receipt projection does not turn it into a hidden proof claim.
`ChioProofClaims` support for other proof families is not evidence that a
Finding can carry a hidden range or outcome predicate. Such a profile would
need a versioned carrier and an explicit trusted-signer-to-claim mapping; M2
rejects any attempted hidden-predicate upgrade.

#### 4.1.1 M2 offline evidence-verifier profile

M1's `verify_finding` proves artifact integrity only. It does not turn receipt
references, cost, intent, bond, status, or a guarantee label into verified
claims. M2 adds a named `FindingEvidenceVerifier` profile at the buyer
boundary. Its input is a size-bounded raw `chio.finding.v1` byte string plus
explicitly configured trust roots, resolver policy, trusted time, and the
resolved evidence bundle. Its order is normative:

1. Strict-parse the raw Finding before ordinary deserialization, reject
   duplicate keys, unknown fields, non-I-JSON integers, invalid id/signature,
   and expired validity. A canonical-only endpoint must additionally compare
   the submitted raw bytes with the computed canonical bytes;
   canonicalization alone normalizes rather than rejects alternate key order
   or whitespace.
2. Resolve every unique evidence receipt into an atomic
   `{canonical_receipt_bytes, receipt_sha256, checkpoint,
   checkpoint_sha256, inclusion_proof}` input. Full-receipt mode strictly
   reconstructs and verifies canonical receipt bodies with strict Ed25519
   verification and weak-key rejection. It does not reuse the existing loose
   receipt, checkpoint, lineage, or export-envelope helpers as an authority
   boundary. Checkpoint verification cross-checks the wrapper checkpoint and
   receipt sequences, log identity, range, leaf index, tree size, both roots,
   canonical leaf bytes, signer/key epoch, validity, revocation, and every
   inclusion-path field. `ReceiptInclusionProof::verify` alone is
   insufficient because it verifies only its inner path against a
   caller-supplied root. The recomputed receipt ids, their order, and their
   cardinality must equal `Finding.evidence_receipt_ids` exactly, with no
   extras or omissions, and every checkpoint identity/reference must equal
   `Finding.evidence_checkpoint_ref`. A projected-disclosure mode instead authenticates
   only the disclosed projection statements under the profile's externally
   pinned BBS projection authority, including issuer fingerprint/key, epoch,
   validity, rotation, revocation/status source, and trusted registry. An
   embedded BBS issuer key never self-authorizes. Projected mode reports full
   receipt authenticity, checkpoint membership,
   hidden metadata, and cost facets as unavailable unless their exact
   required inputs are separately carried and verified. The deterministic
   wedge requires full-receipt mode.
3. Verify issuer-to-evidence provenance: the Finding issuer must be the
   producing subject or be connected through a configured, authenticated
   delegation/lineage rule. A matching payload digest alone is not
   provenance.
4. Verify the replay-recipe preimage when present. Its strict canonical digest
   must match, and its runner, tool manifest, inputs, environment, resource
   bounds, and verdict predicate must be supported by the selected verifier.
   The final recipe separately commits the cycle-free pre-run
   descriptor/protocol-template digest described below; it may then add the
   outcome-derived payload commitment and claimed verdict without pretending
   they were known before execution.
5. Verify an intent commitment only from its own atomic receipt/checkpoint
   reference. Its parameter hash commits to a strict, versioned pre-run
   template containing descriptor topic/context, protocol and verifier-profile
   digests, runner/tool/manifest, immutable inputs/environment, resource
   policy, and the allowed predicate/outcome vocabulary. It excludes the final
   payload digest, producing receipts, selected outcome class, and claimed
   verdict. The final replay recipe must bind this exact template digest.
   Ordering is proved by checkpoint sequence on one pinned log, or by a
   profile-approved anchored cross-log time relation; otherwise the facet is
   unavailable.
   The verifier enforces checkpoint continuity and any anchor requirement
   selected by the profile. The commitment must predate every producing
   receipt. This gives protocol-hindsight resistance for the published
   Finding, not completeness: sellers can precommit many trials and publish
   only favorable ones.
6. Verify `evidence_cost` as a lower bound only in full-receipt mode, with two
   non-interchangeable facets. `metered_exposure_backing` requires an admitted
   kernel, mediated reconciled exposure, and matching signed nonce, and yields
   only kernel-accounted metered exposure. `settled_spend_backing` additionally
   requires qualifying capture or finalized settlement evidence and yields
   kernel-accounted settled spend. Add exact-currency amounts with checked
   arithmetic; do not use the advisory saturating cost rollup as authority.
   Neither facet proves paid honest work, physical compute burn, total effort,
   or completeness. Projected mode leaves both unavailable until a later audit
   supplies the full authority inputs.
7. Resolve `bond_ref` to the live, exclusive allocation described in F1 and
   verify its seller/listing/finding, schedule, class, currency, amount,
   expiry, and remaining-exposure bindings against a fresh authority-signed
   allocation snapshot. A stale bundle reports bond liveness as unavailable,
   not verified.
8. Evaluate guarantee and evidence-class consistency without upgrading one
   facet from another. At M2 the verifier can report an authenticated online
   status observation if configured, but it cannot report portable
   `status_fresh`; that facet requires the M6 sparse proof.
9. When `runtime_assurance_tier` is present, resolve the exact appraisal and
   runtime-attestation inputs, verify their signatures, measurements,
   freshness, trust roots, producing-receipt linkage, and tier mapping under
   the profile, and report `runtime_assurance_backing`. A seller label or an
   unrelated attestation cannot make this facet verified. When the field is
   absent, no assurance facet is required or inferred.

The result is a structured facet report, not one Boolean:
`artifact_integrity`, `receipt_authenticity`, `checkpoint_membership`,
`kernel_and_revocation_trust`, `issuer_lineage`, `recipe_binding`,
`intent_binding`, `metered_exposure_backing`, `settled_spend_backing`,
`runtime_assurance_backing`, `bond_backing`, `status_liveness`, and
`guarantee_consistency`. Each facet is
one of `verified`, `asserted`,
`unavailable`, or `failed`, with evidence references and reasons. Every facet
required by the profile or a present Finding claim must be exactly `verified`;
`asserted` and `unavailable` deny listing activation or purchase for that
requirement. A `failed` facet always denies because it records a check that ran
and contradicted its evidence.
`chio finding verify` renders this report and never collapses `asserted` or
`unavailable` into a verified badge.

The verifier profile and its report do not bootstrap their own authorities.
Deployment configuration pins distinct governance-root, venue-admission,
verifier-report, M4 purchase/failed-delivery, collateral,
seller-authorization, appraisal/runtime-attestation, and BBS projection roles,
including authority identity, key/fingerprint and epoch, validity, rotation,
revocation/status source, trusted registry, and resolver policy. The reusable
profile names the verifier-report and purchase roles and their key-lifecycle
requirements before any Finding is authored, while deployment governance
independently pins those authorities. Each
artifact body names its authority, and the envelope signer must equal that
configured role and the body authority. Embedded-key verification alone is
never sufficient.

When the report authorizes venue admission, it is a signed, registered
`chio.finding.verifier-report.v1` artifact, not an unsigned CLI rendering. It
binds the Finding id and canonical envelope digest, verifier-profile id and
digest, verifier implementation id, trust-root/key-status snapshot, resolved
evidence-bundle digest, evaluation time, every facet result and reason, and
the authority key. The admitted verifier profile names the report-signing
authority and its validity, rotation, and revocation policy. Unknown,
out-of-window, or revoked report keys fail admission. The venue admission
cross-binds the exact report id and envelope digest. A buyer may rerun the
same verifier locally, but an unsigned local result is buyer policy and
cannot substitute for the admitted report or authorize value movement.

### 4.2 Delivery receipt metadata (two blocks, two milestones)

Review finding: the kernel must not attach fields it cannot source from
verified inputs. `OutputDigestSha256` carries only the digest, so at M3
the kernel can truthfully attest exactly that - the finding-specific
context arrives at M4, when the bid-mint extension gives it a SIGNED
carrier. Two blocks, following the typed-metadata-block pattern
(`governed_transaction`, `economic_authorization`;
`spec/PROTOCOL.md:906-988`):

**M3, generic: `chio.delivery-contract.v1`** - sourced from values the kernel
can verify: `expected_output_sha256` (from the externally authored,
provider-signed token constraint), `observed_output_sha256` (the
kernel-derived digest of the final post-transform output preimage), and
`digest_check: matched | mismatched` (the kernel's comparison). A concrete
matched output may appear only on Allow; a concrete
mismatch produces a signed Deny carrying the expected and observed digests
without disclosing the payload. For the M4 v1 finding profile, the final
output MUST also be the unchanged seller-origin envelope under the identity
pipeline rule in 4.5/6.2. An operator-policy transform never becomes a
seller-attributed `mismatched` result. Pre-dispatch portable rejection and
output kinds with no defined digest representation deny without fabricating
an observed digest block. This generic block is usable by any
output-committed tool call, not only findings.

**M4, finding overlay: `chio.finding.delivery.v1`** - the fields below,
attached only when the grant carries a provider-signed
`Constraint::RequireFindingPurchase` marker with exact `finding_id`,
`listing_id`, and a closed settlement selector. The selector is either
`LocalReversibleHold` with no settlement-profile digest or
`CrossOrgEscrow { settlement_profile_sha256 }`. M4 defines both shapes even
though the second remains disabled until M7. This signed selector prevents an
escrow purchase from downgrading into the local hold/capture path by omitting
its companion witness. The fields below are attached only when
the purchase context arrives through verifiable artifacts. The marker is
the downgrade-resistant discriminator that the current bid token lacks:
`bid()` drops the pricing scope, and `OutputDigestSha256` is intentionally
generic, so neither can tell the kernel that omitted finding context must
deny.

The M4 purchase chain uses one exact transport. Governed-intent context key
`context.chio_finding_purchase_context_b64` contains base64 of at most 256 KiB of
   strict canonical `chio.finding.purchase-context.v1` JSON. The encoded-length
bound is checked before allocation or decoding; the decoded bound is checked
again before strict raw parsing. The context contains the signed Finding,
   venue admission, market terms, verifier profile, exact signed verifier
   report, issuer-signed seller authorization, seller backing, listing,
   pricing hint, original `SignedBidRequest`, `SignedAskResponse`,
`SignedAcceptedBid`, exact token offer, and reservation reference or witness.
M7 does not insert its later escrow witness into this object. F6 carries that
signed witness through one separate bounded context key and binds it to the
SHA-256 digest of these already complete canonical purchase-context bytes,
which avoids a self-hash cycle.
This opaque
carrier is necessary because ordinary deserialization into
`serde_json::Value` loses the raw representation needed to reject duplicate
keys. Missing, malformed, non-canonical, oversized, or unknown-field context
denies before a budget, nonce, payment authorization, or tool invocation is
mutated.

The signed `chio.finding.v1` is the anchor that binds identity to commitment.
No ask, bid, or pricing artifact independently carries the
`finding_id -> payload_sha256` link. Admission verifies all of these
cross-bindings:

1. **Request and grant selection.** The actual request has the exact
   provider-authorized server id and tool `read_finding`; its argument object
   contains exactly the string `finding_id`, and that value equals both the
   marker and verified Finding. The original bid requested that same
   server/tool, `max_invocations: 1`, and exact
   `finding:<finding_id>` scope. Exactly one matching token grant is selected.
   It is DPoP-bound, has one invocation, one
   `OutputDigestSha256(finding.payload_sha256)`, and one
   `RequireFindingPurchase` whose exact ids and settlement selector match the
   admitted rail. Local mode requires no escrow-witness context key and rejects
   one if supplied. Cross-org mode requires that key and its exact
   settlement-profile envelope digest. Missing, extra, duplicate, conflicting,
   multi-grant, wrong-tool, wrong-server, extra-argument, and ambiguous
   selections deny. The selected `(grant_index, digest, marker)` is frozen in
   durable admission and must match on replay.
2. **Artifact integrity.** Strict verification recomputes the Finding content
   address and issuer signature, and verifies the venue admission,
   issuer-signed seller authorization, seller backing, market terms,
   governance verifier profile, verifier report, listing, pricing, bid, ask,
   and accepted-bid envelopes. The admitted
   terms/profile/report digests remain
   bound through reservation, purchase, challenge, and enforcement. The token
   presented to the kernel must be
   canonical-byte identical to `ask.body.token_offer`, not merely share its
   id, subject, or expiry. The token issuer signs the ask; the pricing hint
   signer, listing id, and `capability_scope = finding:<finding_id>` match.
3. **Authorized seller and payee.** The listing publisher, registered finding
   server, pricing/ask/token issuer, and payment beneficiary are the Finding
   issuer, or each is covered by the unexpired
   `chio.finding.seller-authorization.v1` whose scope names this finding,
   listing, `read_finding`, and settlement destination. The verified commerce
   payee binding uses `SellerExact` or a
   provider-signed subject-to-destination mapping and equals the listing
   beneficiary. A copier cannot relist another issuer's artifact and route
   payment to itself. Missing delegation, wrong beneficiary, and alternate
   payee deny before financial authorization.
4. **Buyer and handshake.** The original bid and accepted bid verify under the
   token subject key, or under an authenticated agent-to-payer-key mapping
   that explicitly names that subject. Their `agent_id`, listing id,
   `bid_digest`, canonical ask digest, quoted price, token id, full subject,
   and expiry all cross-bind. An opaque `agent_id` alone never establishes
   payer identity.
5. **Reservation.** `bid_receipt_id` is buyer-supplied text until resolved
   against authoritative state. In the M4 single-operator profile, the
   durable reservation record binds its id to the payer public key, canonical
   original signed bid, ask digest, exact venue-admission envelope digest,
   listing, currency, amount, preallocated `purchase_intent_id`, and stable
   `authoritative_payment_operation_id`. The minimal
   `SignedReservationReceipt` is only a signed compatibility pointer to that
   record; every reveal re-resolves the durable state and rejects a missing,
   changed, canceled, expired, or already-consumed operation. The
   qualified profile requires exact equality, not merely "at least," across
   the listing price, ask and accepted bid, both capability ceilings, governed
   quote, budget reservation, payment authorization, and capture. M7
   additionally verifies the settlement authority's signed
   cross-org witness with those same fields. The reservation is a budget and
   seller-exposure reservation only, not evidence that external payment was
   captured.

Only after all five does the kernel stamp `finding_id` from the anchor.
`accepted_bid_ref` is recorded as reservation-backed only because step 5
proved it. When the signed grant carries `RequireFindingPurchase`, malformed,
missing, extra, or settlement-mode-incompatible purchase artifacts deny;
silent omission or fallback would allow a downgrade.
Omission of the overlay is legitimate only for generic output-committed calls
whose grants lack that marker. The kernel never infers the profile from a
listing or pricing scope that the token does not retain.
Caller-asserted copies without those signed artifacts are never promoted
into this block (P10 discipline). The `status_proof` sub-block is NOT
part of M4: it is a signature-safe addition completed at M6, which breaks
the former M4-to-M6 dependency cycle. The field remains optional on the wire
so M4 receipts decode after the additive change, but every M6-qualified
purchase/reveal requires it and an absent block cannot support
`claim.finding.status_fresh`:

| Field | Semantics |
|---|---|
| `finding_id`, `listing_id` | what was delivered |
| `expected_payload_sha256` | the commitment the delivery was checked against |
| `digest_check` | `matched` or `mismatched`; `matched` is the only value on an Allow |
| `expected_media_type`, `observed_media_type`, `media_type_check` | strict reveal-envelope media binding; only `matched` may appear on an Allow |
| `transform_profile` | `identity` in v1, asserted only after the kernel proves the applicable post-invocation pipeline was empty and the seller-origin envelope was not mutated |
| `purchase.bid_digest`, `purchase.ask_digest`, `purchase.accepted_bid_ref` | handshake binding |
| `status_proof.feed_id`, `status_proof.key_domain_nonce`, `status_proof.map_epoch` | (M6, optional-additive) kernel-verified fixed key domain and advancing signed sparse-map epoch |
| `status_proof.status_epoch_artifact_sha256`, `status_proof.proof_sha256`, `status_proof.root_hash` | (M6, optional-additive) digests of the verified epoch artifact, strict portable proof input, and signed root |
| `status_proof.non_inclusion_checked_at` | (M6, optional-additive) kernel-verified freshness time |

The Allow receipt for `read_finding` carrying these blocks, under the
`chio.mediated_spend.v1` conjunction (`receipt/authoritative_spend.rs`), is
the **reveal proof**: disputes anchor on it (F4), and the M7 settlement
authority consumes it with checkpoint inclusion to issue the release receipt
the escrow adapter accepts (F6). It is not itself settlement-anchor material.
Note `content_hash` on the receipt body already
equals the served bytes' digest by WYSIWYS construction
(`receipt/signing.rs:273`); `expected_payload_sha256` records what it was
required to equal. Per the C2 boundary above, this proves a
kernel-attested reveal, not buyer retention.

### 4.3 Challenge and signed outcome (M5)

`chio.finding.challenge.v1` is a signed, origin- and class-gated submission.
Its outer JSON Schema `oneOf` and Rust validator require exactly one origin:

- `buyer_submission` binds the envelope signer to `challenger`, class-specific
  standing, a live class-specific Dispute lock, and the collected dispute-fee
  terminal naming the admission-pinned challenge-administration pool principal
  and rail destination; or
- `venue_audit` binds the envelope signer to the admitted audit authority and
  carries the exact signed audit epoch, selection, and authorization digests.
  It has no challenger, standing purchase, Dispute lock, dispute fee,
  forfeiture, or reward fields.

Cross-origin fields reject. Common fields bind challenge, Finding, listing,
admitted market terms, governance verifier profile, seller backing, and filing
time. For `evidence_invalid` and `replay_contradiction`, buyer-supplied M4
purchase refs establish standing only. For `digest_mismatch`, standing comes
from a signed `chio.finding.failed-delivery.v1` record, because the
pre-capture Deny correctly creates no purchase record. The failed-delivery
record binds the buyer, accepted-bid envelope digest, authoritative
reservation and payment-operation ids, hold attempt and exact release
terminal, checkpointed mismatch Deny, Finding/listing/delivery blocks, zero
realized spend, and `payout_eligible: false`. Each receipt reference is an atomic
`{receipt_id, receipt_sha256, checkpoint_ref, checkpoint_sha256}` tuple and
carries no payout address or asserted buyer/amount.

Inside either origin, a second `oneOf` admits exactly one evidence branch:

- `digest_mismatch`: the checkpointed marked identity-profile Deny plus its
  accepted-bid/hold attempt;
- `evidence_invalid`: the exact contested Finding evidence tuples; or
- `replay_contradiction`: the strict cycle-free recipe preimage plus ordered
  `{receipt, checkpoint, observation_bytes}` tuples sharing one
  `replay_run_id`.

The guarantee/evidence compatibility matrix is closed and normative:

| Challenge class | Admissible Finding class | Required standing |
|---|---|---|
| `digest_mismatch` | any guarantee/evidence class, but only the marked identity-output M4 profile | exact signed failed-delivery record |
| `evidence_invalid` | `evidence_class` is `observed` or `verified`, and the contested evidence was required by admission | exact signed finalized purchase record |
| `replay_contradiction` | `guarantee_class = deterministic_replay`, `evidence_class = verified`, and a committed recipe | exact signed finalized purchase record |

Every other pairing rejects before evaluation. This matrix is the concrete
validator rule; no placeholder compatibility carrier remains.

The seller, not the challenger, precommits the rule through
`chio.finding.market-terms.v1`, and governance admits it under
`chio.finding.challenge-verifier-profile.v1`. That profile pins receipt and
checkpoint keys by role, runner manifests, resolver/retention and key
validity/rotation/revocation policies, the buyer, audit, outcome, enforcement,
purchase, and generic market-penalty-authority roles, resource caps,
class-specific challenge-bond limits, and the closed predicate vocabulary.
For `chio.registry.market-penalty.v1`, the envelope signer, body `issued_by`,
and configured governing operator must all name that exact penalty authority.
The evaluator's generic trusted-signer parameter is not ambient authorization.
A mutable trusted-key set cannot authorize value movement. Unknown, expired,
not-yet-valid, or revoked role keys make evaluation indeterminate or deny
enforcement, as the predeclared profile specifies; rotation never silently
rewrites an already admitted authority snapshot.

Replay execution and adjudication are separate. An effectful governed
`ReplayExecutor` resolves venue-retained content and runs the recipe. It emits
strict `chio.finding.replay-observation.v1` bytes binding recipe/profile,
phase, runner manifest, resolved input bundle, environment, terminal result,
exit code, and report digest; the terminal receipt action binds the same
run/recipe/profile/phase and its `content_hash` equals the observation digest.
The pure evaluator performs no fetch, tool call, clock read, or storage
access. It verifies supplied bytes and role-authorized receipt/checkpoint
evidence, then applies the closed predicate. Every class returns the
class-independent decision `Upheld | Rejected | Indeterminate`. Only the
`replay_contradiction` branch also carries the nested replay result
`ConfirmedContradiction | Consistent | Indeterminate`, mapping respectively to
those three decisions. The digest and evidence branches map their own closed
mechanical predicates directly. Timeout, unavailability, resource exhaustion,
network attempt, runner error, malformed output, or an unresolved
trust/profile input is `Indeterminate`, never seller fraud.

The recipe commits the Finding context and payload digest, immutable
source/corpus/environment inputs, exact canonical parameters,
payload-application phases, runner manifest, profile digest, limits, closed
predicate, and claimed verdict. It does not include `finding_id`, which would
create a hash cycle. The challenge and observations cross-bind the resulting
recipe digest to the signed Finding.

For `digest_mismatch`, the evaluator verifies both delivery blocks, selected
grant, and `transform_profile: identity`; generic mismatch, wrong media, and
operator-policy transform denials cannot sanction the seller. For
`evidence_invalid`, only affirmative invalidity under the profile effective
at publication qualifies: a bad signature, contradictory checkpoint proof,
semantic cross-binding failure, or a key proven revoked or compromised then.
Missing bytes, resolver outage, retention/SLA failure, or later revocation is
indeterminate or a separate operator event. No class grants discretionary
semantic adjudication.

The buyer challenge lock is live, exclusive collateral bound to challenger,
challenge, active schedule, Dispute class, class-derived amount/currency,
expiry, and unspent state. A compare-and-set transitions it once to
`returned` or `forfeited`. `Upheld` returns it; `Rejected` applies the
predeclared class-specific return/forfeit rule. `Indeterminate` creates no
seller hold or sanction and never forfeits for infrastructure or availability
failure. It may retain the same lock only through one bounded, signed retry
window using the same challenge, fee, lock, profile, and evidence identity,
then transitions to `IndeterminateClosed` and returns it exactly once. A
recognized venue audit instead carries the signed `chio.finding.audit-epoch.v1`
authorization and later links its attempts and outcome through
`chio.finding.audit-report.v1`. It has no Dispute bond, dispute fee,
forfeiture, or reward; the audit-only participation-fee pool pays only
verified selected-audit execution, and a clean audit transfers nothing to
the seller.

One defect/liability spans all challenge classes and evidence subsets:

```text
defect_key =
  H("chio.finding.defect.v1", finding_id)

liability_key =
  H("chio.finding.liability.v1",
    defect_key, venue_id, listing_id,
    seller_collateral_allocation_id,
    chain_id, vault_contract, vault_id)

purchase_key =
  H("chio.finding.purchase.v1",
    signed_accepted_bid_envelope_digest,
    authoritative_payment_operation_id)
```

The reservation coordinator allocates
`authoritative_payment_operation_id` before budget, exposure, or rail effects,
binds it to the exact admission/bid/ask/Finding/listing/payer state, and makes
the accepted bid's compatibility receipt id resolve to that frozen record.
Neither the seller, buyer, nor finalizer may choose the id after observing an
effect.

Challenge/evidence/replay-run ids are separate deduplication or corroboration
keys and cannot authorize another slash. Challenge state is
`Submitted -> Evaluating -> Rejected | IndeterminateRetryable |
IndeterminateClosed | Upheld`. `IndeterminateRetryable` follows the bounded
same-lock rule above and never enters liability state; retry success reaches
an ordinary verdict, while retry expiry or the one allowed retry remaining
indeterminate reaches `IndeterminateClosed`. Liability state is
`Open -> UpheldPendingClaims -> PendingAppeal -> Finalizing -> Settled`, with
`ReversedBeforeImpairment` as the successful-appeal terminal. The first
upheld challenge linearizes its `Open -> UpheldPendingClaims` CAS, listing
sales block, and authoritative purchase cutoff in the same listing-scoped
store used by M4 purchase finalization. M4 reserves a monotonically ordered
pending-purchase slot before capture; once the block commits, no later slot
can capture. The claim snapshot waits for every pre-cutoff pending slot to
reach its signed Allow/purchase-record or Deny terminal, so a concurrent
capture cannot land after the cutoff or be omitted. Cumulative compensation
for a `purchase_key` across every class/liability cannot exceed its
authoritative realized spend.
`Finalizing -> Settled` is a separate durable CAS, not shorthand for
impairment submission. It requires confirmed final seller
impairment/distribution, every required challenge-lock and fee terminal, and
the post-impairment M6 status insertion evidenced by the exact signed epoch
and inclusion proof. Until all required effects reconcile, the liability
remains `Finalizing`, `publication_pending` remains set, and purchases stay
blocked across restart.

Challenge-carried purchases are standing hints, not the payout set. During
the signed nonzero claim window, the venue enumerates the M4 purchase records
at the frozen cutoff, commits the snapshot, accepts omission proofs, and
seals one allocation. A deployment without this index discloses
first-come/omitted-victim risk. The predeclared formula is:

```text
computed_exposure = checked_add(base_finding_stake,
                                open_per_sale_encumbrances)
require computed_exposure <= listing_requirement.required_amount
slash = min(live_allocated_collateral,
            computed_exposure)
buyer_pool = min(slash, total_uncompensated_realized_spend)
community_fund = slash - buyer_pool
```

M2 admission binds exactly one `Listing` requirement, requires it to be
slashable, and enforces exact currency equality plus
`base_finding_stake + maximum_sale_exposure <= required_amount` with checked
arithmetic. Duplicate Listing requirements reject. This is necessary because
the shipped evaluator selects the first matching requirement and treats
`required_amount` only as a per-penalty ceiling; it is not live collateral or
a cumulative exposure bound. M5 repeats the ceiling and currency checks
against a fresh, finalized bond snapshot. A computed exposure above the
signed requirement rejects as inconsistent state; it is never silently
clamped to that requirement. High-sale concurrency cannot raise the computed
penalty past that ceiling.

The buyer pool is pro rata by realized spend with deterministic remainder
order by `purchase_key`; destinations come from immutable M4 rail-tagged
payment records. Exact-sum checking alone does not enforce harmed-party
destinations, so the finding-specific settlement choke point also enforces
the ADR-0015 policy allowlist in its signed operator-mediated authorization.
Current on-chain exact-sum validation does not structurally enforce that
allowlist; ADR-0015 follow-up A remains required for that stronger claim.
Qualified `digest_mismatch` releases the M4 hold and has zero realized
monetary harm. Finalized `evidence_invalid` and
`replay_contradiction` purchases may qualify.

The admitted outcome authority signs `chio.finding.challenge-outcome.v1` over
the challenge, origin, class-independent decision, optional nested replay
result, exact verifier-profile and evidence-bundle digests, and facet results.
The verifier rejects a signer outside the profile's effective
validity/rotation/revocation snapshot. Only `Upheld` enters the penalty lane.
The registered existing-v1 penalty envelope then uses
`OpenMarketAbuseClass::FraudulentListing` and exactly one
`OpenMarketEvidenceKind::External` reference. That reference must set
`reference_id` to the exact outcome id and `sha256` to the lowercase canonical
signed-envelope digest. Its `uri` is absent when the envelope is carried
inline, or is a profile-allowed immutable content-addressed URI resolving to
that same digest; a mutable or unresolved URI rejects.

The finding-specific wrapper registers the current
`chio.registry.market-penalty.v1` body/envelope at M5 without changing its
frozen fields or enums, then narrows all three shipped branches. Every branch
requires exactly one Listing requirement, exact computed amount/currency,
live allocation, the External outcome binding above, a clean
`evaluate_open_market_penalty` result, and a separate clean generic-governance
evaluation. An outer `Ok` is not authorization because the shipped evaluator
returns findings on failure.

- Pending: `HoldBond`, penalty `Enforced`, an enforced Sanction case,
  effective `BondHeld`, `blocks_admission = true`, empty findings, and a
  slashable Listing requirement.
- Successful appeal: `ReverseSlash`, penalty `Reversed`, an enforced Appeal
  case cleanly bound to the original Sanction by both
  `appeal_of_case_id` and `supersedes_case_id`, effective `Appealed`, empty
  governance findings, resolved as the authoritative case head,
  `blocks_admission = false`, and `supersedes_penalty_id` naming the exact
  prior clean `HoldBond`. The transition records
  `ReversedBeforeImpairment` as the authoritative admission head so the
  superseded Sanction no longer blocks admission. The same liability,
  outcome, amount, and currency must match; an Open, Escalated, expired, or
  otherwise unresolved Appeal, a prior `SlashBond`, or post-impairment
  reversal rejects.
- Final: `SlashBond`, penalty `Enforced`, the enforced Sanction, effective
  `BondSlashed`, `blocks_admission = true`, empty findings,
  `supersedes_penalty_id` naming the exact clean `HoldBond`, and the exact
  held predecessor. It may run only after appeal finality.

The pending branch blocks sales and freezes the purchase cutoff. The venue
completes the signed claim/omission window and freezes the authoritative
purchase snapshot and deterministic allocation before entering
`PendingAppeal`. Exactly three appeal-final inputs exist: no filing by the
signed deadline, a terminal denied Appeal, or the enforced successful Appeal
above. The first two advance to `Finalizing`; the third reverses before
impairment. Open, Escalated, expired-with-findings, unresolved, or
unavailable Appeal state remains held and enters a fail-closed operator
quarantine, never an assumed denial. The Sanction case, HoldBond penalty, and
their signer/key-status evidence must remain valid through the full
claim/appeal/finalization horizon, or a separately specified signed successor
must preserve their exact semantic identity. Silent expiry cannot authorize
or erase value movement. The admitted enforcement authority then signs
`chio.finding.challenge-enforcement.v1` over the final liability, exact
outcome and penalty envelopes, fresh finalized bond snapshot, purchase
snapshot, allocation, vault, destinations, and sequence-independent semantic
effect-intent ids. Publisher-only sequence/transaction attempt keys are
excluded. Signer authorization and key validity/rotation/revocation are
rechecked against the admitted profile. Post-impairment
reversal/restitution is unsupported in v1.

External effects have domain-specific identities, not one generic
liability/effect tuple:

- seller impairment/payout (unbatched v1):
  `H("chio.finding.effect.seller-impair.v1", chain_id, vault_contract,
  liability_key, allocation_digest)`;
- buyer challenge-lock disposition:
  `H("chio.finding.effect.challenge-bond.v1", challenge_id, lock_id)`, with
  the exact `returned | forfeited` value and amount in a separately compared
  canonical intent digest so conflicting dispositions collide and reject;
- dispute-fee reimbursement:
  `H("chio.finding.effect.fee.v1",
  buyer_submission_id_or_audit_run_id, fee_operation_id)`;
- retraction insertion:
  `H("chio.finding.effect.retraction.v1", finding_id, feed_id,
  retraction_intent_id)`; and
- root semantic intent:
  `H("chio.finding.effect.root-intent.v1", operator_id, root_domain,
  liability_key, outcome_id, final_penalty_envelope_digest,
  allocation_digest)`.

The finality CAS first persists `publication_pending`, the signed enforcement,
and these sequence-independent semantic intent ids before any external
impairment. Bond-root publication then serializes or leases the registry's
global strict-next operator sequence and derives the publisher-only attempt
key `H("chio.finding.effect.root-publish.v1", root_intent_id,
assigned_sequence)`. That attempt key, prepared calldata, and transaction
nonce are not fields of the earlier enforcement artifact. The root commits
the exact anchored enforcement receipt/action whose leaf is the global
`evidenceHash`. Only a finalized root authorizes the impairment broadcast.
`EvidenceAlreadyUsed` counts as success only when finalized transaction input
and receipt prove the exact stored call; the current event, private consumed
map, and cumulative bond snapshot are insufficient to reconcile an ambiguous
same-size concurrent impairment, which must quarantine absent a contract
getter/event extension.

Actual status insertion is ineligible until appeal finality and confirmed
impairment, although `publication_pending` was durable before impairment and
continues to deny sales. Identical effect retries reconcile and conflicting
ones reject. Seller slash goes only to verified harmed buyers and the
pre-sale-pinned community fund. Independent challenger replay-cost
reimbursement comes only from the separately collected dispute-fee
administration pool. The recurring seller participation fee is collected per
admitted listing/audit epoch and is audit-only.

### 4.4 Status feed

The feed borrows the existing revocation-oracle operator, key, epoch, anchor,
and broadcast patterns, keyed by finding id
(`RevocationKey { subject_id, epoch_nonce }` generalizes;
`crates/trust/chio-revocation-oracle/src/api.rs:70`). It does not reuse the
current root semantics. Retraction inserts come from the seller (voluntary)
or final finding enforcement with confirmed impairment (F4), never from a
bare outcome or reversible hold.

The standalone `chio.finding.status-epoch.v1` artifact, registered at M6,
signs a new domain-separated sparse-map root body. It canonically binds
`status_map_version: sparse_map_v1`, a fixed finding-status signature domain,
`feed_id`, numeric `key_domain_nonce`, monotonically advancing `map_epoch`,
`operator_key`, `root_hash`, tree depth, hash/empty-node parameters,
generated/validity times, and anchoring refs.
The artifact uses the existing operator key representation and signing
primitive, but it is not an unchanged `EpochRoot` or `SignedEpochRoot`
envelope. Its outer signature covers the version and domain together with
the root. An ordinary revocation-oracle signed root, a root from another
feed, or a sparse root with a different version/domain must fail strict
parsing or signature verification, even if the numeric nonce and root bytes
match. `EpochNonce` is a `u64`; M6 selects one numeric value for
`key_domain_nonce` in the `chio.finding.status.v1` domain, and every insert
and proof uses exactly `(finding_id, that numeric nonce)`. A label is not a
wire nonce. `map_epoch` is a separate root-generation counter and advances
monotonically; it never changes the keyed retraction domain.

Despite its filename, the current `InMemoryRevocationOracle` is an
append-only ordinary Merkle tree plus a local `HashMap`; its
`NonInclusionProof { key, epoch_root, checked_at }` carries no path, and
`verify_non_inclusion` consults local state
(`api.rs:110-114`, `sparse_merkle.rs:1-79`). A path cannot retrofit portable
absence against that root. M6 therefore adds a durable, transactional,
domain-separated, versioned true sparse authenticated-map backend for finding
status. Leaves, epochs, and monotonic feed state survive restart. It reuses
signer infrastructure, anchoring transport, and broadcast plumbing, but uses
the new signed body above and enforces cross-backend rejection.

M6 registers one unsigned strict `chio.finding.status-proof-input.v1` with a
closed tagged `oneOf`. Both `non_inclusion` and `inclusion` carry the exact
signed canonical `chio.finding.status-epoch.v1` envelope bytes, feed id,
fixed key-domain nonce, advancing map epoch, finding id, artifact id/digest,
exact sparse-map root, path, and freshness bounds. Inclusion additionally
binds the exact retracted value and retraction-intent digest. Cross-branch
fields reject. The unsigned input never substitutes for the signed epoch it
carries.

The request carries the size-bounded canonical proof JSON as base64 under one
reserved governed-intent key,
`context.chio_finding_status_proof_b64`. This opaque encoding preserves exact
bytes across the already-deserialized `serde_json::Value` context. Kernel
admission decodes and strict-parses it, then verifies the carried epoch signer
against the status operator and key policy pinned in venue admission. Schema,
signature, version/domain, artifact digest, path, key/feed/nonce/epoch/finding
cross-bindings, anchor, and freshness must all match before the kernel emits
overlay fields. CLI/SDK verification is additional defense, not the source
of a kernel-signed claim. V1 requires this portable input; a bare root,
caller-asserted operator, or authenticated online query response cannot enter
the overlay.

Freshness includes rollback protection, not just a wall-clock window. Each
kernel and buyer persists a high-water `(map_epoch, epoch_id, root_hash)` per
admission-pinned feed/operator identity plus every locally observed retracted
key. A proof below that map epoch rejects even if its signature remains valid;
the same map epoch with another id/root rejects; and a locally retracted
Finding never becomes live through a later non-inclusion proof. Authorized
key rotation preserves the feed identity, fixed key-domain nonce, and
monotonic map-epoch floor under a signed rotation policy. An unknown key or
attempted epoch reset fails closed.

Signed fresh roots prove consistency, not insert completeness. At M5 appeal
finality, the single-operator profile atomically persists final enforcement,
`publication_pending`, and the idempotent retraction intent before external
impairment; pending denies new purchases. The status publisher may execute
that intent only after the exact impairment is finalized. It inserts the key,
advances the durable sparse map, signs the next epoch, and returns the strict
inclusion input covering it. Only then may the coordinator clear pending.
Restart and duplicate-delivery tests prove the coupling. Voluntary or
cross-operator retraction completeness remains an audited assumption backed
by a live operator bond, signed retraction-intent receipt, published inclusion
SLA, and mechanically evidenced alert/slash policy. A fresh root that omits
such an intent is censorship, not evidence that no intent exists.

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
- The v1 finding-delivery profile, selected by M4's
  `RequireFindingPurchase` marker and its exact settlement mode, is
  identity-only: the committed envelope is the
  seller-origin tool output and MUST equal the final receipt content preimage
  byte-for-byte after canonicalization. The current `PostInvocationHook`
  contract has no static effect declaration, so v1 does not guess which
  hooks can mutate. Admission requires
  `PostInvocationPipeline::is_empty()` for a marked finding reveal
  (`post_invocation.rs:58-75,181-210`) and rejects every non-empty pipeline
  before dispatch. Durable admission freezes that empty hook-identity
  sequence in its post-return plan; finalization validates the frozen plan
  and asserts that the seller-origin envelope was not mutated
  (`kernel/admission_coordinator.rs:944` pattern). The kernel configuration
  setters require exclusive mutable access, and replay under a different
  hook plan fails closed rather than silently changing the profile. The
  finding overlay records `transform_profile: identity` from these
  kernel-verified facts. A redaction, replacement, or any other non-empty
  post-invocation policy is a policy-incompatibility Deny with the selected
  release/refund/compensation state, never seller-attributed
  `digest_mismatch` evidence.
- A future transform-aware profile is a versioned design change. It must bind
  the exact transform pipeline and version in the finding and grant,
  preserve authenticated seller-origin and final digests plus the transform
  trace, and assign transform-induced mismatch to operator policy rather
  than the seller. M3 does not claim or implement that profile.
- The envelope's `media_type` MUST equal the signed artifact's
  `payload_media_type` (review finding: the digest gate only checks the
  envelope hash, so without this rule a seller could advertise
  `text/x-diff` while committing to some other type, and a buyer that
  auto-applies on the advertised type is misled). Under the marked M4
  profile, the kernel strict-parses the final value as the exact two-field
  reveal envelope, validates bounded base64, and checks
  `envelope.media_type == finding.payload_media_type` after the digest check
  but before capture or any other financial finalization. A mismatch emits a
  signed Deny with `media_type_check: mismatched`; it can never produce an
  Allow or charge the reveal price. The buyer repeats the check before
  interpreting the bytes. M5 does not make this mismatch slashable:
  `evidence_invalid` remains limited to the Finding's production-evidence
  receipts/checkpoint. A future delivery-semantics challenge class would need
  its own checkpointed reveal evidence and explicit seller-fault rule.
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

Prerequisite: the externally pinned governance root signs a reusable,
cycle-free `chio.finding.challenge-verifier-profile.v1` before the replay
recipe is authored. The profile contains role/trust policy but no Finding id,
recipe digest, listing id, report id, or backing id. The recipe commits that
profile's envelope digest; the Finding then commits the recipe digest. A
Finding-scoped profile would recreate a hash cycle and is invalid in v1.

0. (Optional, priced-in) Before running the work, the producer commits the
   strict versioned pre-run descriptor/protocol template via a mediated call.
   The template binds topic/context, verifier profile, runner/tool/manifest,
   immutable inputs/environment, resource policy, and allowed
   predicate/outcome vocabulary, while excluding the final payload digest,
   producing receipts, selected outcome class, and claimed verdict. Its
   receipt is the pre-outcome intent commitment later referenced as
   `intent_commitment_receipt_id` (4.1). M2 authenticates its semantics and
   ordering, and the final replay recipe commits the exact template digest
   before adding outcome-derived fields. A generic non-empty receipt id or a
   parameter hash over context alone earns no priced uplift.
1. Producer agent finishes the work; its receipts and cost metadata already
   exist as a side effect of mediation.
2. Assemble `chio.finding.v1`: seal the payload (seller-side storage), digest
   it, reference the evidence receipts + checkpoint, commit the replay recipe
   (wedge), sign.
3. M2 stores the strict canonical Finding and retained recipe/dependencies
   content-addressed, exposes immutable resolution by `finding_id`, and builds
   a bounded paginated descriptor index. It projects a generic listing and a
   signed pricing hint whose scope is `finding:<finding_id>`. M2 requires
   `price_hint_ref` to be absent for this Finding-scoped projection, avoiding
   the Finding-id/hint-digest cycle; the venue admission binds both exact
   signed envelopes. Existing generic listing search does not load Finding
   descriptors or liveness, so this projection and index are new M2 wiring,
   not shipped query behavior.
4. The Finding issuer signs `chio.finding.seller-authorization.v1` for the
   exact Finding, listing, seller/delegate, provider server/tool, payment
   beneficiary or provider-signed payee mapping, validity window, and
   revocation/status reference. This artifact is required even when issuer
   and seller are the same key, so direct and delegated cases share one
   verification path. The seller signs cycle-free
   `chio.finding.market-terms.v1`, which binds the already admitted reusable
   verifier-profile envelope digest.
5. Before the evidence report is produced, the configured collateral
   authority creates `chio.finding.bond-backing.v1`, bound to seller,
   authorization, Finding, listing, terms/profile, canonical fee-schedule
   requirement digest, Listing class, currency, concrete
   vault/chain/operator epoch, locked amount, maximum exposure, nonzero
   claim/audit/appeal/settlement horizons, expiry, and unique allocation id.
   The terms bind the requirement and collateral policy, not the later
   backing-envelope digest, so the order has no hash cycle.
   `OpenMarketBondRequirement` has no native id, and an opaque `bond_ref` or
   transient `BondBacked` result is not live collateral. Stale, wrong-party,
   wrong-currency, duplicate-class, underfunded, already-encumbered, or reused
   allocations reject.
6. The M2 verifier now evaluates every evidence and live-backing facet and
   signs `chio.finding.verifier-report.v1`. This ordering prevents a report
   from claiming bond verification before the backing exists. The configured
   report, governance, venue, collateral, and Finding-issuer roles are
   independently pinned; no embedded key or report/profile pair can
   self-authorize the other.
7. Activation is an idempotent publication transaction. It authenticates the
   payer and schedule, collects the publication fee and first recurring
   seller participation-fee epoch on an evidenced rail to the exact
   governance-pinned audit-pool principal and rail-tagged destination,
   restricts 100 percent of participation revenue to audits, persists
   terminal receipts naming that beneficiary, consumes the dedicated backing,
   and atomically indexes or writes a replay-safe outbox. Governance separately
   pins the challenge-administration pool principal/destination for later
   dispute fees; the two pools cannot substitute for one another. The venue
   signs `chio.finding.admission.v1` over the Finding,
   issuer-signed seller authorization, listing, hint, exact verifier-report
   id/digest, terms/profile, fee terminals with exact rail beneficiaries,
   backing, both pool identities/destinations and authority epochs, the
   registered community-fund destination, status-feed operator profile, the exact M4
   purchase/failed-delivery authority identity plus key epoch and
   validity/revocation snapshot, and liveness.
   Its body venue identity and envelope signer equal the externally configured
   venue authority. Trusted search/bid/purchase require a current admission bundle;
   unpaid later audit epochs make the listing non-admitted.
8. Each purchase atomically reserves
   `encumbrance_per_sale = k * accepted_price`, `k >= 1`, and requires
   `base_finding_stake + sum(open_encumbrances) <=
   min(locked_amount - slashed_amount,
   listing_requirement.required_amount)`, with checked arithmetic and exact
   currency equality. It also enforces the admitted
   `maximum_sale_exposure`. Backing expiry
   extends beyond the sale plus every liability horizon and settlement
   buffer. Because the vault caps beneficiary addresses rather than
   purchases, the minimal unbatched EVM profile admits at most 15 distinct
   immutable buyer payout destinations per liability horizon, reserving one
   of 16 slots for the admission-pinned community-fund remainder. Neither a
   challenger nor an enforcement caller may replace that destination.
   Repeated purchases to
   an existing destination do not consume another slot. A broader profile
   needs a globally committed replay-safe batched allocation and may not
   truncate victims.
9. M8 may publish a fully admitted pheromone hint. Indicator JSON alone is
   not a deposit: its subject/namespace, listing scope, signer/passport,
   severity, confidence, decay, nonce, subject-class policy, and cost must
   verify, and a buyer always re-resolves the current admission before buying.

The M8 convention fixes subject `finding_listing_hint`, namespace
`dev.chio.cognition-market`, severity `medium`, confidence `0.75`, a 3,600
second half-life, evaporation floor `0.01`, one configured treaty, and a
non-empty nonce. Its strict indicator binds the Finding id, listing id,
current signed listing-envelope digest, current M2 admission-envelope digest,
and `finding:<finding_id>` capability scope. Receiver policy requires the
exact non-destructive `SubjectClassPolicy`, a signed passport/deposit, real
scarcity and replay admission, and an observation-cost commitment in the
protocol unit below the configured cap. A positive deposit remains a
discovery hint: the buyer re-verifies the current namespace-owned listing,
pricing signature, and full M2 admission bundle, and the hint grants no
purchase authority.

### F2. Discover and verify (buyer, pre-purchase, no payment yet)

1. Buyer hits the same failing context; computes `context_sha256`; searches
   M2's bounded descriptor index by topic prefix plus exact digest, resolves
   the immutable Finding by id, and revalidates its current venue admission.
   The shipped generic `ListingQuery` does not perform this descriptor match.
2. Run the M2 `FindingEvidenceVerifier` profile in 4.1.1. The current buyer
   boundary (`crates/trust/chio-attest-buyer/src/api.rs`) supplies useful
   receipt-verification primitives, but it does not ship this aggregate
   profile. Buyers consume its per-facet report and apply listing policy;
   artifact integrity never stands in for evidence, lineage, cost, intent,
   bond, liveness, or guarantee verification.
   Evidence-sharing modes (the X2 side-channel trade-off made explicit):
   pre-purchase verification needs receipt bytes, and full receipts carry
   exact `cost_charged` in their financial metadata, re-leaking what a
   bucketed `evidence_cost` hides. Sellers therefore choose per listing:
   (A) full-receipt evidence - receipt, checkpoint, and exact-cost facets
   can be verified pre-purchase, and the exact cost profile leaks; the wedge
   default for org-internal contexts; or
   (B) projected evidence - BBS-projected statements revealing only supported
   fixed receipt slots while hiding the `metadata` slot
   (`chio-selective-disclosure` 14-slot projection). That projection is not a
   full receipt, checkpoint, or Finding semantic-evidence schema. Its profile
   may claim only the authenticated disclosed statements; receipt
   authenticity, checkpoint membership, hidden semantic inputs, and cost are
   `unavailable` unless separately proven. A policy requiring those facets,
   including the deterministic wedge policy, rejects projected mode. Cost
   claims verify only at audit or post-purchase. Correspondingly,
   `evidence_cost` granularity in the artifact is seller-chosen
   (bucketing is legitimate); no validator requires it to equal the
   receipt sum pre-purchase. A false rollup becomes `evidence_invalid`
   material only when the challenge supplies the authenticated cost receipts
   and the predeclared evidence-mode rule establishes enough coverage to make
   the contradiction mechanical.
3. At M2, apply the configured authenticated online status observation and
   report its trust mode. At M6, require the portable sparse non-inclusion
   proof in 4.4 inside the freshness window. The current local-state
   `verify_non_inclusion` path (`api.rs:116`) is not a portable proof.
4. Buyer computes its local elicitation ceiling (MECHANISMS section 2); if
   posted price is above it, walk away. The shipped `MeteredBillingQuote` is
   caller-supplied and does not authenticate how a re-derivation estimate was
   produced, so neither kernel nor venue may report the bid basis as true.
   M8 does not add a signed quote producer. The estimate remains private buyer
   policy.
5. The M8 Rust, TypeScript, and Python helpers bind the caller-carried
   estimate to the expected source, context, replay-recipe digest, exact
   currency, and validity window. Amount and basis-point arithmetic uses
   canonical decimal strings, `u64` bounds, checked wide intermediates, and
   one floor after the combined product. Basis points outside `0..=10000`,
   unsafe JavaScript numbers, negative or fractional values, NaN encodings,
   substitution, currency mismatch, staleness, and overflow reject. A
   `SignedBid` still reveals only the resulting ceiling.
6. When a buyer uses a shared pool, the kernel verifies the signed
   `chio.finding.pool-allocation.v1` companion against the exact canonical
   `SwarmBudgetPool` digest and pinned authority before handing a debit to a
   qualifying backend. `pool_sha256` is the SHA-256 of the RFC 8785 canonical
   `chio.swarm.budget-pool-digest-projection.v1` preimage, not the JSON bytes
   of `chio.swarm.budget-pool.v1`. The projection carries the planning
   object's schema as `poolSchema`, preserves allocation order, and encodes
   `totalUnits` plus every allocation unit field as the shortest unsigned
   base-10 string (`0` or a nonzero digit followed by digits). The shipped
   SQLite backend serializes debits, persists exact replay, and uniquely binds
   one purchaser allocation to the pool id. Advisory remote budget views
   cannot make this hard-ceiling claim.

### F3. Purchase and reveal (single-operator / wedge path)

This is the target M3/M4 flow, not current M1 behavior:

1. `BidRequest` uses the exact request profile in 4.2. The provider
   `AskResponse` mints one DPoP `read_finding` grant with
   `max_invocations: 1`, `max_cost_per_invocation: price`,
   `max_total_cost: price`, expiry, exactly one digest constraint, and exactly
   one purchase marker. `bid()` currently hardcodes
   `constraints: Vec::new()` (`bidding.rs:396`), so M4 extends
   `BidMintContext` and rejects any provider mint that is missing, duplicate,
   conflicting, or outside the authorized seller profile.
2. Before `accept()`, an authoritative buyer/kernel coordinator verifies the
   current admission and participation-fee epoch, atomically reserves the
   exact budget and seller liability exposure, preallocates stable
   `purchase_intent_id` and `authoritative_payment_operation_id`, and persists
   a rich durable reservation record keyed to the payer public key, canonical
   original bid and ask, exact venue-admission envelope digest,
   listing/Finding, exact amount/currency, and expiry. It then produces the
   minimal signed `SignedReservationReceipt` as a compatibility pointer to
   that record. The existing
   pure `accept()` does not create that reservation: it verifies the supplied
   `VerifiedReservationReceipt` and signed ask, then copies the receipt id
   into `SignedAcceptedBid`. The M4 wrapper additionally requires exact amount
   equality and every Finding cross-binding before calling it. Re-resolving
   the accepted bid's receipt id recovers the same preallocated
   purchase/payment identities; no post-effect caller value can choose them.
   Participation
   is recurring per listing/audit epoch, not a per-purchase buyer fee.
   Neither the authoritative budget reservation nor `accept()` authorizes or
   captures the reveal price. The current
   reserve-for-caller `MustPrepay` path is not usable here: even when its
   adapter first returns `Held`, it captures that hold before returning the
   reservation. Calling that state a reversible reservation would be false.
3. Buyer invokes `read_finding`. Before any nonce, budget, payment, or
   dispatch mutation, the kernel performs the strict purchase-context,
   request, selected-grant, seller/payee, buyer-key, and reservation checks
   in 4.2 and proves the identity output pipeline. ADR-A adds a distinct
   reveal-time rail transition: after guards pass but before dispatch,
   authorize the quoted price as a reversible `Held` payment without
   capturing it. Dispatch, apply the frozen empty post-invocation plan, then
   verify digest, strict envelope shape, bounded base64, and media type.
   Only a fully matched result advances. Before capture, the durable
   finalizer stores the validated output, frozen bindings,
   `matched_pending_capture` terminal plan, receipt nonce and timestamp,
   receipt signer/key epoch, policy-result digest, complete metadata template,
   and a monotonically ordered pending-purchase slot under the same
   listing-scoped fence used by M5's sales block and cutoff. It then captures
   idempotently, records the rail transaction, signs/persists the one frozen
   Allow with both delivery blocks and
   `chio.finding.purchase-record.v1`, closes that slot, and only then releases
   the response to the buyer. The purchase record binds purchase key, buyer,
   exact venue-admission envelope digest, accepted and realized spend, seller
   backing/encumbrance, delivery and payment evidence, and immutable
   rail-tagged refund/compensation destination. Its signer must be the purchase
   authority pinned by the venue
   admission and verifier profile; validity, rotation, and revocation are
   checked at purchase and again before any M5 payout.
4. Every other terminal is explicit and replay-stable. Authentication,
   policy, or preauthorization failure creates no new debit, capture, fee,
   nonce, or invocation mutation. Because the pre-accept budget and seller
   exposure reservations already exist, the coordinator idempotently
   cancels/releases both under the signed failure terminal, or their explicit
   expiry transition does so; it never describes them as nonexistent.
   Server abort, digest mismatch, media mismatch, or persistence failure
   before capture releases the rail hold and applies the ADR-A-selected
   budget/exposure transition before a signed Deny is returned. A marked
   identity-profile digest mismatch first signs and persists the Deny, then
   closes the pending-purchase slot to that signed Deny terminal. It then
   checkpoints the Deny. Only after that checkpoint is available may the purchase
   authority sign `chio.finding.failed-delivery.v1` over the buyer, accepted
   bid, authoritative reservation and preallocated payment operation, hold
   attempt and release, exact Deny/checkpoint binding, zero realized spend,
   and payout-ineligible state. Until phase two completes, the failure is
   pending and grants no M5 standing. The final artifact creates no purchase
   record and is the only buyer-standing carrier for an M5
   `digest_mismatch` challenge. Checkpoint outage therefore delays standing
   without leaving an M5 cutoff slot open.
   A crash after capture resumes
   from the staged output and capture journal to the same signed Allow and
   recovery authorization; it neither captures again nor pretends the final
   transfer can be released. Capture is forbidden unless the replayable
   terminal material was durably staged first. An output policy mutation is
   an operator-policy incompatibility, not seller fraud.
   `MustPrepay` and `PrepaidFinal` are excluded from the v1 finding profile;
   supporting either requires a later version with durable, evidenced,
   exact-once compensation rather than a fictional refund.
5. Buyer ingests via a governed memory write; provenance chain binds
   store/key to the purchase capability and write receipt
   (`memory_provenance.rs:63`), and M4 records a typed lineage edge from that
   write receipt to the verified finding-delivery receipt. M6 uses this edge
   for quarantine resolution; current `MemoryProvenanceEntry` alone does not
   carry a finding id.
6. Paid-but-lost-payload edge (fine detail, M4): with `max_invocations: 1`,
   a buyer that crashes between the Allow receipt and persisting the
   payload has paid for bytes it no longer holds. Correction (review
   finding): the `Operation::ReadResult`-on-the-grant option does NOT
   work today - `grant_matches_request` matches only grants containing
   `Operation::Invoke` (`request_matching.rs:337-347`) and there is no
   kernel `ReadResult` request path, so such a grant authorizes no re-read.
   The original one-shot grant is consumed by the successful reveal, and a
   receipt is evidence rather than invocation authority. M4 therefore
   chooses an explicit recovery authorization. The provider's recovery
   service verifies the checkpointed original Allow plus buyer DPoP, then
   mints a no-charge grant to the original delivery-token subject. Its
   request constraints bind the original signed receipt id, original
   capability id, and finding id; its output digest remains the Finding
   commitment. The grant has a zero monetary ceiling, no authorization or
   capture path, a short expiry, and a bounded retry count. Recovery
   admission re-verifies the trusted-kernel receipt and every
   subject/capability/finding binding before serving, and records a
   recovery-to-original-delivery lineage edge. Checkpoint visibility alone
   cannot authorize a third party. A kernel-native receipt-keyed result store
   remains a future alternative, not the M4 design.

### F4. Challenge, audit, and slash

1. A buyer challenger, or the venue's published-rate audit scheduler,
   presents exactly one class of mechanical evidence: a checkpointed
   identity-profile mismatch Deny, the Finding's invalid evidence subset and
   checkpoint, or mediated reproduction receipts for the committed recipe.
   Venue selection is itself verifiable: each round commits the eligible
   listing snapshot and randomness source before sampling, then publishes
   signed selection, attempt, completion, and missed-audit receipts. Without
   those artifacts random auditing is an operator assumption, not an
   enforceable rate.
2. Assemble `chio.finding.challenge.v1` with exactly one origin branch and one
   class branch. A buyer signs its branch and atomically locks the admitted
   class-specific Dispute allocation and fee. A venue audit is signed by the
   admitted audit authority, binds its epoch and selection authorization, and
   has no Dispute bond, fee, forfeiture, or reward. Cross-origin fields reject.
3. Any replay work runs through the governed executor first. The pure
   evaluator then checks strict observations and the owning branch (4.3),
   rejecting cross-class inputs and returning the class-independent decision.
   `Indeterminate` follows the same-lock bounded retry and creates no hold or
   sanction; retry exhaustion enters `IndeterminateClosed` and returns the
   lock exactly once. `digest_mismatch` is live only for authenticated
   seller-origin mismatch under the marked identity profile. Generic digest,
   wrong-media, and output-policy denials cannot trigger seller sanction.
4. An upheld outcome atomically creates a reversible `HoldBond`, changes the
   listing-scoped liability head, blocks new purchase slots, and freezes the
   purchase cutoff in the same authoritative store used by M4 finalization.
   It waits for all already-issued slots at or below that cutoff to close,
   then completes the signed claim/omission window and seals the authoritative
   purchase snapshot and deterministic allocation before entering
   `PendingAppeal`. The signed nonzero appeal window then runs before any
   impairment or append-only retraction. A successful enforced Appeal clears
   only the unapplied hold with `ReverseSlash` and supersedes the original
   Sanction as the admission head; v1 rejects post-impairment reversal.
5. After appeal finality, the venue maps the already signed outcome through
   the exact typed final `SlashBond` branch in 4.3 and requires clean generic
   governance and market-penalty evaluations. It then signs the finding
   enforcement artifact over that exact final penalty, persists
   `publication_pending` plus every sequence-independent semantic effect
   intent, and enters `Finalizing`. The finding-specific choke point verifies
   the immutable allowlisted exact-sum distribution and fresh finalized bond
   snapshot before `prepare_bond_impair`; current on-chain code alone does not
   prove harmed-party destinations.
6. The bond-root publisher obtains the serialized operator sequence, publishes
   and finalizes the unique liability-bound enforcement receipt/action root,
   then the impairment worker broadcasts and confirms the exact prepared call.
   Challenge-lock disposition and fee reimbursement use their separate effect
   keys. Only confirmed impairment unblocks the already-durable retraction
   intent for M6 publication. Every intent precedes dispatch, identical retry
   reconciles, and ambiguous external state quarantines. Purchases remain
   denied while publication is pending. Post-impairment correction requires a
   future funded restitution and correction-status design.

### F5. Retract and propagate

1. After confirmed impairment, the durable outbox inserts the exact
   `(finding_id, key_domain_nonce)` key into the status oracle, retries idempotently
   across restart, obtains a new signed epoch plus strict inclusion input,
   records them against the authenticated enforcement and impairment, and
   only then clears publication pending. After every other required
   impairment, distribution, challenge-lock, and fee terminal has also
   reconciled, the coordinator performs the one durable
   `Finalizing -> Settled` CAS. Missing status inclusion or any ambiguous
   effect leaves the incident in `Finalizing` and purchases blocked.
2. Buyers' subscription (or next purchase attempt) observes the root;
   holders of the finding use an opt-in quarantine profile. M6 injects a
   synchronous `FindingRetractionResolver` into `MemoryGovernanceGuard`,
   backed by verified memory provenance, the typed write-to-delivery lineage
   edge, receipt/capability lineage, and an authenticated local status-root
   cache. It resolves store/key -> write -> delivery -> finding -> status.
   Missing/tampered lineage, unavailable provenance/status stores, stale
   roots, pending publication, and retracted status deny fail-closed; the
   default non-market memory profile is unchanged.
3. M6 adds a typed dependency edge directed
   `dependent_memory_write_receipt -> source_finding_delivery_receipt`, plus a
   reverse query from the source delivery to all dependent writes for
   blast-radius inspection. Existing lineage query primitives
   (`chio-lineage/src/query.rs:56`) are useful building blocks but do not
   automatically wire purchased Finding descendants. Automatic invalidation
   of derived data stays out of scope (threat model A5 boundary).
4. Refunds on retraction are a POLICY choice recorded in the listing terms,
   not a protocol mechanism: if offered, they ride the existing
   claim/settlement lane, never a discretionary re-route (ADR-0015).

### F6. Cross-org purchase (escrow path)

M7 depends on M4 purchase binding, M5 dispute terminals, and M6 portable
status. It is blocked on ADR-C, which must choose between a contract-gated
Finding escrow profile and an explicitly trusted off-chain profile around the
current contract. The current `ChioEscrow` does not inspect Finding artifacts,
disable `releaseWithSignature`, or disable partial proof release, so a
no-contract-change deployment cannot claim cryptographic full-only or
settlement-authority enforcement. M7 retains M4's budget, request, grant,
identity, output, and media checks, but replaces the single-operator
reveal-time rail hold/capture with funded escrow and proof-gated release.
The provider-minted grant must select
`CrossOrgEscrow { settlement_profile_sha256 }` and that digest must equal the
verified settlement-profile envelope. A local selector, missing or extra
escrow-witness context, or any profile mismatch denies before mutation; the
kernel never falls back to M4 local capture.

0. Before escrow creation or funding, resolve and verify the exact
   governance-signed settlement profile and live, non-reusable
   mediator-backing envelope. Atomically reserve that backing allocation for
   the expected chain, contract, escrow terms, purchase, mediator, amount,
   currency, liability horizon, and one effect path. A missing, reused,
   stale, underfunded, or wrong-profile allocation rejects before buyer funds
   move.
1. Before `accept()`, the buyer or an explicitly authorized sponsor creates
   and finally funds the escrow and the authoritative reservation service
   verifies that state. Its reservation binds the exact signed bid/ask,
   Finding/listing, buyer key, `EscrowTerms.depositor` address or signed
   sponsor/delegation, capital-instruction id and signer, refund destination
   exactly equal to `EscrowTerms.depositor` and the `createEscrow` caller,
   contract-derived `escrowId`, seller beneficiary, accepted currency and
   amount, expiry, and the exact settlement-profile and consumed
   mediator-backing envelope digests/allocation id. Sponsor authorization
   acknowledges that any timeout refund returns to that sponsor/depositor,
   not to a separate buyer address.
   The shipped `ReservationReceipt` omits several of
   these fields, so its signed carrier is accepted only when an authenticated
   finding-aware adapter derives it from that stronger durable authority
   state. The existing pure `accept()` then verifies the supplied reservation
   and creates `SignedAcceptedBid`.
2. Only after `SignedAcceptedBid` exists, the configured settlement authority
   re-observes the same funded and final escrow and signs
   `chio.finding.escrow-witness.v1`. The witness binds chain id, contract and
   contract-derived escrow ids, every observed ABI `EscrowTerms` field,
   block/hash/finality reference, Finding/listing and the SHA-256 digest of the
   exact canonical `chio.finding.purchase-context.v1` bytes, accepted bid and
   token ids, settlement-profile and mediator-backing envelope digests,
   backing-allocation consumption id, buyer/payer/depositor-or-sponsor
   mapping, refund destination equal to the depositor, seller beneficiary,
   mediating operator key, exact amount, currency, token
   address/decimals/config epoch, deadline, and reservation id. It does not
   invent a canonical-JSON `EscrowTerms` digest as the on-chain
   identity. Absent, unfunded, underfunded, overfunded, wrong-party,
   wrong-token/config/currency, expired, non-final, or reorged witnesses deny
   before invocation. The qualified token allowlist excludes fee-on-transfer,
   rebasing, and otherwise non-exact transfer behavior.
   Governed-intent context key
   `context.chio_finding_escrow_witness_b64` carries only this strict canonical
   signed envelope as size-bounded base64. The kernel checks encoded and
   decoded bounds and strict-parses both context keys before any nonce, budget,
   payment, or invocation mutation. It recomputes the purchase-context digest
   and requires the witness binding to match. The witness is never nested in
   the purchase context, so this two-key M7 carrier is cycle-free.
3. The existing settlement helper expects a standard anchored Chio receipt,
   not an arbitrary Finding delivery or
   `chio.finding.settlement-release.v1` envelope. After the matched delivery
   receipt is checkpointed and anchored, the settlement authority verifies it
   and signs the application decision. The release body binds the escrow
   witness, delivery receipt/checkpoint, accepted bid, purchase context,
   settlement-profile, and mediator-backing envelope digests, plus Finding,
   listing, capability, escrow, parties, amount/currency, backing-allocation
   consumption id, and authority epoch. It does not bind its own envelope
   digest or `settlement_reference`. After signing, the
   finding-aware wrapper verifies the complete release envelope and defines
   the standard receipt field `settlement_reference` as lowercase
   `sha256_hex(canonical_json_bytes(input))`, where `input` is the strict
   versioned object

   ```json
   {
     "schema": "chio.finding.settlement-reference-input.v1",
     "signed_release_envelope_sha256": "<hex64>",
     "escrow_witness_envelope_sha256": "<hex64>",
     "delivery_receipt_and_checkpoint_sha256": "<hex64>",
     "signed_accepted_bid_envelope_sha256": "<hex64>",
     "purchase_context_sha256": "<hex64>",
     "settlement_profile_envelope_sha256": "<hex64>",
     "mediator_backing_envelope_sha256": "<hex64>"
   }
   ```

   All digest strings are exact lowercase hex64. The struct rejects unknown
   fields, and a checked-in golden vector freezes its canonical bytes and
   output digest. It is an internal digest preimage, not another signed
   artifact or self-reference. This construction order is cycle-free.
   A profile-pinned operator-kernel then produces the standard Chio settlement
   receipt whose signing nonce equals
   the dispatch capital instruction's `governed_receipt_id` and whose
   `content_hash` is
   `settlement_anchor_receipt_content_hash_parts(execution_receipt_id,
   settlement_reference, dispatch_id, governed_receipt_id)`. That receipt is
   checkpointed into an `AnchorInclusionProof`, paired with the exact
   `SettlementAnchorContentBinding`, and supplied by the finding-aware wrapper
   to
   `prepare_merkle_release(..., EscrowExecutionAmount::Full)`. The resulting
   typed escrow proof root is then published before the beneficiary submits
   the full release. The three evidence stages are distinct: delivery
   inclusion, settlement-authority receipt inclusion, and typed escrow-root
   publication. Wrong signer, nonce, content binding, receipt, escrow,
   capability, purchase, amount, beneficiary, root, or replay rejects.
4. The deadline is derived, not caller-selected. At funding time it must be
   at least
   `max(now + reveal_window, token_expiry) + delivery_checkpoint_delay +
   delivery_anchor_finality + authority_receipt_checkpoint_delay +
   authority_receipt_anchor_finality + settlement_root_publication_delay +
   settlement_finality + safety_margin`. The witness records every selected
   bound. This gives the buyer the full grant lifetime to reveal and still
   leaves enough time for all three proof stages. A tighter deadline rejects.
5. The finding-qualified state machine permits only `FullReleased` for the
   exact accepted price or `FullRefunded` for the entire unreleased deposit.
   It rejects `partialReleaseWithProof*`, any partial or mixed economic
   terminal, and amount drift. The contract requires the beneficiary to call
   release, so a restart-safe watchdog verifies and publishes the proof,
   notifies the seller beneficiary to submit the full release, observes
   finality, and otherwise allows the permissionless full refund after the
   deadline. It cannot claim power to release on the beneficiary's behalf.
   Contract pause can block release through the deadline while refund remains
   available, so that case ends in full refund. A later zero-value refund call
   after a confirmed full release does not reverse value and is classified as
   an ignored observer artifact, not a mixed terminal. The watchdog persists
   signed transitions, handles reorg rollback before finality, and rejects
   terminal replay. These are internal durable coordinator states, not a new
   signed artifact family. The workspace currently has verifier artifacts for
   watchdogs but no job scheduler, so the operator must run this worker under
   the M7 runbook.
6. A matched delivery first opens a durable
   `matched_pending_escrow_settlement` purchase slot under the same
   listing-scoped fence and liability cutoff used by M4/M5. It is not yet a
   finalized purchase record and carries no realized spend. A confirmed
   `FullReleased` terminal closes the slot and signs
   `chio.finding.purchase-record.v1` with the exact settlement profile,
   consumed mediator backing, release decision, settlement receipt/root,
   finalized transaction, beneficiary balance delta, realized spend equal to
   the accepted amount, immutable buyer destination, and `payout_eligible:
   true`. A confirmed `FullRefunded` terminal closes it with zero realized
   spend, refund transaction/evidence, and `payout_eligible: false`. M5
   standing and compensation accept only finalized captured or
   `FullReleased` branches with positive authoritative realized spend. Crash,
   reorg, and retry cannot create both terminals or count pending/refunded
   value as seller-fraud loss.

`ChioEscrow` releases against the operator named in `EscrowTerms`, so that
identity is part of the fair-exchange trust model. The v1 profile allows only
a registered, buyer-allowlisted neutral or mutually trusted mediating kernel.
Under the current contract, the settlement authority must be that exact
operator: a distinct authority has no cryptographic release gate. Moreover,
the operator and beneficiary can bypass the off-chain Finding profile through
other shipped release methods. ADR-C must either add a contract-level
full-only/authority discriminator or classify this as an audited TTP profile
that remains Experimental and makes no non-discretionary claim.
The same operator key must appear in the listing deployment record, escrow
witness, `EscrowTerms`, delivery checkpoint, and settlement release receipt.
A seller-aligned mediator and a non-mediating checkpoint signer are both
disallowed.

`EscrowTerms.operatorKeyHash` is fixed at creation, while release checks the
current operator key. M7 therefore forbids in-place key substitution for a
funded escrow: planned rotation drains qualified escrows by full release
before rotation, and any escrow that cannot do so reaches full refund after
its deadline. A new key requires a new escrow witness. Emergency rotation may
force that refund path and must not be described as seamless release.

M7 registers governance-signed `chio.finding.settlement-profile.v1` and
bond-authority-signed `chio.finding.mediator-backing.v1`. The profile pins the
operator and role keys, exact contract path, token/currency/decimal/config
mapping, release-receipt producer, all deadline stages, full-only terminal
policy, and objective SLA/penalty mapping. The non-reusable backing allocation
binds that operator, chain, contract, profile, currency, amount, liability
horizon, and expiry. Missed checkpoint, authority-root, or settlement-root
deadlines feed the profile's mechanically evidenced operator-penalty path.
Without these artifacts and their effect path, withholding a root imposes no
necessary loss on the mediator and the flow must not claim an
incentive-compatible release guarantee. A final observer also verifies the
beneficiary balance delta equals the accepted token amount before recording
`FullReleased`.

DPoP is mandatory, so a seller plus mediator cannot replay a bearer token
without the buyer. It still does not prove that the buyer process retained
the response. A malicious mediator can invoke, sign, checkpoint, suppress
the response, and release escrow. Neutral-mediator operation is therefore an
explicit trusted-third-party assumption. With a seller-aligned mediator the
residual is high and the profile is prohibited. Buyer acknowledgments invert
the theft direction and remain out of v1 absent a predeclared
acknowledgment-versus-refund rule. M7 tests both root withholding and response
withholding and states which event is mechanically compensable.

Evidence and passport exchange ride the bilateral evidence-share surfaces
(`chio evidence export/import`, federation policy artifacts). The
operator-visibility caveat (threat model O1/T1) applies; TEE-tier kernels are
only a mitigation under a separately qualified measured-runtime profile.
Current TDX verification and the injected boot verifier port do not by
themselves establish that profile. Transport-level federation remains bounded to what ships
(ADR-0014 defers mesh transport to Year-2).

## 6. Kernel enforcement points (delivery contract)

The digest gate is the one genuinely new output-enforcement obligation:
**no Allow receipt for `read_finding` unless the served bytes hash to the
committed `payload_sha256`.** Current main has separate durable and legacy
terminal lanes, and no single Allow builder covers both. The carrier remains
a viable candidate, but enforcement placement now requires ADR-A and kernel
owner review. M4 separately adds the purchase-context, reservation, and
identity-output admission obligations.

### 6.1 The facts that constrain the design

Status note: PR #974 landed as `51e46336b` and is an ancestor of the
`9ec6814a2` implementation baseline. The earlier pre-#974 pipeline analysis
is superseded by these facts, verified against post-#974 main:

- **F-A. The production durable financial path runs post-invocation
  hooks.** `evaluate_durable_post_return_output` materializes the tool return
  and calls `apply_durable_post_invocation_pipeline` before producing the
  terminal output (`kernel/admission_coordinator/terminal.rs:390-428`).
  Redaction and other transforms therefore run before the durable receipt
  hash is computed.
- **F-B. Durable hook `Block` is not a delivery-contract denial.** The
  durable hook evaluator rejects `Block` as a violation of its non-blocking
  contract (`post_invocation.rs:261-275`), and the durable terminal path
  surfaces it as `KernelError::DurableAdmission`
  (`kernel/admission_coordinator/terminal.rs:420-424`). It does not produce
  a signed Deny receipt, a replay-stable mismatch transition, or payment
  compensation. The digest gate cannot be an ordinary blocking
  post-invocation hook.
- **F-C. Constraints remain input-side.** `constraint_matches` receives only
  the constraint and request arguments
  (`chio-kernel/src/request_matching.rs:371`; portable matcher
  `chio-kernel-core/src/scope.rs:193-196`). A new constraint can carry the
  expected digest, but a separate post-return step must compare it with the
  output.
- **F-D. The durable lane exposes the transformed output digest before
  payment planning and settlement.** The terminal finalizer computes
  `receipt_content_for_output` from the post-hook output at
  `kernel/admission_coordinator/terminal.rs:1289`, before
  `durable_payment_disposition` at line 1373 and
  `settle_durable_payment` at line 1527. This is the promising durable gate
  boundary. The same finalizer signs its receipt directly with
  `build_and_sign_receipt` at line 1641, so
  `build_allow_response_with_metadata_and_payee_binding` is not universal.
- **F-E. The legacy charged lane still reconciles before its Allow
  builder.** `reconcile_budget_charge` runs at
  `kernel/validation.rs:2196`, while the legacy Allow builder is called at
  line 2369. M3 must enforce the digest before legacy reconciliation or
  reject digest-constrained reveals from the unsafe legacy lane before
  dispatch.
- **F-F. `PrepaidFinal` can move funds before the output exists.**
  Authorization occurs before dispatch and may advance the durable payment
  journal directly to `PrepaymentSettled`
  (`kernel/validation.rs:2656-2693`). Durable terminal settlement then
  recognizes the already-settled fixed-price journal
  (`kernel/admission_coordinator/terminal.rs:1133-1139`). A post-return
  mismatch cannot be described as a release or reversal on this rail.
  ADR-A must forbid `PrepaidFinal` for digest-constrained reveals or define a
  durable, evidenced, replay-safe compensation transition whose product
  claim names compensation rather than release.
- **F-G. Reserve-for-caller `MustPrepay` is capture, not a reversible
  reservation.** `ensure_reserved_mustprepay_prepaid` authorizes and then
  calls `capture` when an adapter returns `Held` before it returns the
  execution reservation (`kernel/validation.rs:2700-2793`). The returned
  reservation is already funded by settled external value. M4 cannot use
  that path as a pre-reveal hold. ADR-A must introduce a separate budget-only
  accept state plus reveal-time reversible authorization/capture, or name and
  implement compensation for every post-capture failure.

### 6.2 Candidate carrier and ADR-required enforcement contract

**Carrier: a new `Constraint::OutputDigestSha256(String)` variant, minted by
the provider/token issuer into the `read_finding` grant of the
`AskResponse.token_offer`.**
Rationale: the Finding issuer commits the digest in its signed artifact, and
the provider/token issuer must copy that commitment into its signed grant.
The M2 seller authorization proves when those roles may differ. A
buyer-supplied carrier like
`governed_intent.context` is the wrong trust direction. The constraint
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

**Enforcement topology is not yet chosen.** The pre-#974 two-layer design,
including the claim that one common Allow builder covers every path, must not
be implemented literally. ADR-A must define the following contract and
receive kernel-owner review before an M3 implementation plan is written:

- After token verification, output-contract admission resolves exactly one
  matching grant. That grant contains exactly one
  `OutputDigestSha256(lowercase_hex64)`. Duplicate constraints, conflicting
  digests, multiple matching grants, or an index that differs from the
  persisted durable selection deny before budget, nonce, payment, or
  dispatch mutation. Durable state freezes
  `(grant_index, expected_digest)` and terminal replay checks it.
- M3 enables the constraint only for authenticated read-only tool profiles
  whose effect classification is pinned in operator policy. The kernel does
  not enforce advisory manifests, so an untrusted manifest label is not
  enough. Side-effecting, unknown-effect, stream-only, preauthorization-only,
  and no-output surfaces reject before mutation unless a later profile
  defines an irreversible side-effect compensation terminal. An output
  mismatch cannot undo an arbitrary external write.
- A shared, pure digest checker compares `OutputDigestSha256(expected)` with
  the same post-transform `receipt_content_for_output` preimage used by
  receipt signing. A `Stream` output under this constraint denies fail-closed
  unless ADR-A defines and commits a stream digest representation. This M3
  primitive is generic: its mismatch evidence alone says nothing about a
  Finding or seller fault.
- M4's `RequireFindingPurchase` marker and exact settlement selector select
  the v1 identity-output and rail profile. Because hooks expose no static
  effect classification, admission
  requires the applicable `PostInvocationPipeline::is_empty()` before
  dispatch and freezes the empty hook-identity sequence in the durable
  post-return plan. Terminal finalization validates the same plan and asserts
  the seller-origin canonical envelope equals the final receipt preimage. A
  non-empty or changed plan is an operator-policy incompatibility Deny, not
  `digest_check: mismatched` and not seller-fraud evidence. A
  transform-aware finding profile is deferred under 4.5.
- In the durable lane, the checker runs after durable post-invocation
  transforms and before payment disposition or settlement. A mismatch
  requires a persisted, replay-stable terminal transition that emits a
  signed Deny receipt. Its generic delivery block preserves the
  provider-authored expected digest and kernel-derived observed digest with
  `digest_check: mismatched`, and its financial metadata records the
  applicable release, refund, or compensation status. Returning
  `KernelError::DurableAdmission` is not sufficient.
- A matched durable output may authorize capture only after staging the exact
  replayable Allow signing preimage: receipt nonce/timestamp, signer and key
  epoch, selected grant, policy-result digest, complete metadata blocks,
  validated output, purchase bindings, and capture operation. Restart reuses
  that frozen template; it cannot choose a fresh nonce, time, signer, policy
  result, or metadata after observing capture.
- In the legacy lane, the checker runs before `reconcile_budget_charge`,
  with the existing Allow builder used only as a lane-local backstop.
  Alternatively, digest-constrained requests are rejected before dispatch
  whenever unsafe legacy financial dispatch is enabled.
- ADR-A rejects `PrepaidFinal` for v1. M4 accepts a budget-only reservation,
  performs all hard purchase checks, then creates a distinct reveal-time
  reversible rail hold that captures only after digest, envelope, and media
  checks match. Current `MustPrepay` reserve-for-caller cannot implement this
  because it captures a `Held` authorization before returning. If a future
  version permits final prepayment, it must specify durable, evidenced,
  replay-safe compensation and must not call it a release.
- The M4 journal makes the external boundary explicit:
  `budget_reserved -> rail_held -> matched_pending_capture`, followed by
  `captured_pending_allow -> allow_final`. The validated output and
  deterministic Allow inputs are durable before capture. Authorization,
  capture, release, and compensation each carry idempotency keys derived from
  the purchase and terminal operation. Failures through
  `matched_pending_capture` may release the hold; a crash after
  `captured_pending_allow` must finish or replay the same Allow and recovery
  path, not issue a second capture or call the captured transfer reversible.
- Both terminal lanes attach the generic `chio.delivery-contract.v1`
  metadata from kernel-verified values on concrete matched and mismatched
  checks. The finding-specific `chio.finding.delivery.v1` overlay remains
  M4 work, after the signed purchase artifacts and provider-minted grant
  bind a finding id to the expected digest. Once that binding verifies,
  an identity-profile seller-origin mismatch Deny carries both blocks so M5
  can prove which finding was delivered incorrectly without revealing its
  payload. Generic M3 mismatches and transform-policy denials never acquire
  that seller-fraud meaning.
- Adding the constraint requires exhaustive handling in
  `chio-core-types/src/capability/scope.rs`,
  `chio-kernel/src/kernel/governed_validation.rs`,
  `chio-kernel-core/src/scope.rs`, and
  `chio-kernel-core/src/normalized.rs`, in addition to the production
  request matcher and terminal lanes.
- The portable core and browser/mobile adapters are pre-dispatch admission
  evaluators, not output-aware terminal finalizers. M3 must reject
  `OutputDigestSha256` before Allow on those surfaces unless an atomic
  output-aware finalizer is added. A later caller-supplied receipt body and
  content preimage prove WYSIWYS for that body, but the signer does not hold
  the capability constraint and cannot establish the delivery contract.
  Such receipts are excluded from the M3 invariant.

M3 must test the durable reversible-hold lane, `PrepaidFinal` rejection,
transformed output, stream rejection, unpaid durable Allow, and
legacy coverage or fail-closed rejection. Browser, mobile, and direct
portable-core regressions must prove digest-constrained requests reject
before any budget/payment mutation or dispatch unless their surface gains
atomic output enforcement. Tests also cover duplicate/conflicting digest
constraints, multiple matching grants, changed durable grant selection,
unknown or side-effecting tools, and a positive matched Allow carrying the
provider-authored expected digest plus kernel-derived observed/check fields.
Every mismatch test must assert
the signed terminal decision and the exact budget and payment state. M4
separately tests the marked identity profile,
pre-dispatch rejection of every non-empty hook pipeline (including a
redactor), restart/replay rejection when the frozen hook plan differs, a
final no-mutation assertion, and proof that none of those policy paths can
create seller-slash evidence. Its negative matrix covers wrong request
argument/type, alternate token with the same id, wrong grant cardinality,
bid signer or payer-key mismatch, copied listing, expired delegation, wrong
payee/destination, stale or reused reservation, malformed/oversized purchase
context, and media-type mismatch. Each pre-dispatch case proves no budget,
exposure, fee, payment, nonce, or invocation mutation; each post-return
failure before capture proves exact-once hold release and no reveal-price
capture. Crash/restart tests at every M4 journal boundary prove that
post-capture recovery emits the staged Allow without a second capture.

Invariant this creates (formalization candidate, see PLAN):
**kernel-attested reveal soundness** - on every output-enforcement-qualified
terminal profile, a grant carrying `OutputDigestSha256(d)` can produce an
Allow receipt only if the kernel accepted an output preimage with
`content_hash == d`; pre-dispatch-only profiles reject the constraint. The
digest is over the final post-transform output used by receipt signing. This
invariant makes no payment-refund claim unless ADR-A also fixes the rail
policy, and it does not prove that the buyer process received or durably
retained the bytes. The post-Allow crash window remains an M4
delivery-idempotency concern.

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
  server (v1 answer) or api-protect grows response-hash binding. That is a
  deferred engineering extension, not one of the six milestone ADRs.

## 7. Artifact governance and schema evolution

### 7.1 Registration obligations (by schema role)

Section 4 contains several governance classes. They share the public schema
registry but not the signed-artifact allowlist.

Standalone signed artifacts (`chio.finding.v1`; M2 market terms, seller
authorization, verifier profile, verifier report, bond backing, and
admission; the M4 purchase and failed-delivery records; M5 challenge,
outcome, enforcement, finalized bond snapshot, audit epoch/report, and the
existing Rust market-penalty v1 envelope; the M6 status epoch; the M7
settlement profile, mediator backing, escrow witness, and settlement release;
plus an optional M8 re-derivation quote) land in four places:

1. A JSON validation schema at the family-appropriate path:
   finding/challenge/outcome/status/settlement under
   `spec/schemas/chio-finding/v1/*.schema.json` (validated by
   `chio-spec-validate`; the family types are hand-written Rust). The
   `chio.registry.market-penalty.v1` Rust wire type exists, but its public
   strict body/envelope schema is not registered today. M5 registers that
   exact v1 shape without changing its fields or enums.
2. A row in `spec/schemas/registry.json` (`{schema, artifactKind,
   introducedBy, schemaFile}`) plus `spec/schemas/MANIFEST.sha256`.
3. A named schema constant and a `SIGNED_ARTIFACT_SCHEMA_SPECS` row in
   `crates/core/chio-core-types/src/signed_artifact.rs` (the fail-closed
   accept-list for independently signed artifacts).
4. A PROTOCOL.md section under 6.4.x describing the family.

The existing generic `signed_artifact_schema` test proves allowlist entries
have registry counterparts, but does not prove the reverse. Each milestone
therefore adds explicit assertions for every named schema plus a bidirectional
registry/allowlist parity check for standalone signed artifacts. The
`scripts/check-chio-schema-registry.sh` and manifest checks remain separate
required gates. No document treats the current one-way test as complete
four-location proof.

The replay-recipe, purchase-context, replay-observation, and tagged status
proof verifier inputs are unsigned strict wire types. Their
schemas live under
`spec/schemas/chio-finding/v1/`, with registry and manifest rows, typed
parser/validator tests, and PROTOCOL text. None enters
`SIGNED_ARTIFACT_SCHEMA_SPECS`. Replay-recipe integrity comes from strict
canonical bytes hashing to the signed Finding's `replay_recipe_sha256`;
purchase-context integrity comes from verifying and cross-binding every
enclosed signed artifact; status-proof integrity comes from its
strict-canonical digest plus the verified status-epoch artifact, signature,
and sparse path. Their M2/M4/M5/M6 ingress paths apply the size-bound,
strict-raw-first invariant before trusting them.

The two receipt-metadata blocks are not independently signed artifacts.
They are authenticated by the enclosing `ChioReceipt`, like
`chio.admission-receipt.v1`, and therefore MUST NOT receive
`SIGNED_ARTIFACT_SCHEMA_SPECS` rows unless a later design makes them
standalone signed envelopes. Their JSON schemas live under
`spec/schemas/chio-wire/v1/receipt/`, with registry and manifest rows.
Typed receipt structs, reserved metadata keys, enclosing-receipt
canonical/signature round trips, accessor tests, and PROTOCOL receipt
metadata text complete their registration contract (7.5).

### 7.2 Family layout and proof-bundle binding

Template = the commerce-order family
(`crates/platform/chio-commerce-order`: schema ids in `src/ids.rs`, types
`deny_unknown_fields` in `src/types.rs`, per-concern validators, one
top-level `verify_*` in `src/lib.rs:47`, goldens under
`fixtures/proof-room/<family>/<case>/`). The finding family follows it in
the new `chio-finding` crate with goldens at `fixtures/proof-room/finding/`.

Transaction-passport binding adds no new evidence-graph role. The existing
closed, fail-closed `EvidenceNodeRole` vocabulary already includes
`ClaimSet` and `Report`
(`chio-transaction-passport/src/evidence_graph.rs:36,105`); it has more than
eight variants. The finding
verifier binds through the existing `ClaimSet` role by emitting claim ids,
proposed: `claim.finding.delivery_digest_bound`,
`claim.finding.evidence_bound`, `claim.finding.status_fresh`,
`claim.finding.bond_backed` - each carried as a claim-set entry naming the
verifier module and a signed, registered Finding-verifier report, with digest
pins for `payload_sha256` and the evidence artifacts. Unsigned recipe,
replay-observation, and status-proof inputs travel only as content-addressed
non-authority attachments. The report commits their digests and an
independent verifier rechecks role, schema, digest, and semantics; placing an
unsigned input directly in a signed-artifact evidence role is rejected.

### 7.3 Schema-evolution posture (and the listing decision)

The repo's rules, now confirmed: verifier-input artifacts are
`deny_unknown_fields` fail-closed; additive changes are `Option` +
`#[serde(default, skip_serializing_if)]` ("signature-safe": omitted-when-
absent keeps existing signed fixtures byte-stable - exemplar:
`decision_rule_ref` on `LiabilityClaimAdjudicationArtifact`,
`crates/economy/chio-market/src/claim.rs:305`); **adding an enum variant to
a frozen wire enum is normally BREAKING** (no `non_exhaustive`, no
`serde(other)`; the sanctioned route is a new `.v2` schema). The deliberate
exception is the capability `Constraint` vocabulary: its adjacent tag and
hard rejection of unknown variants make the two planned additions
fail-closed for old kernels. `OutputDigestSha256` therefore requires the M3
ADR-A decision, PROTOCOL.md update, exhaustive matcher handling, and
`delivery_contract` corpus rotation. `RequireFindingPurchase` with exact
finding/listing ids and the closed local-or-cross-org settlement selector
requires the corresponding M4 provider-mint design,
PROTOCOL.md update, exhaustive matcher handling, and `finding_purchase`
corpus rotation. No other frozen enum receives this exception. In particular,
`OpenMarketAbuseClass` stays frozen: M5 maps a verified finding violation to
its existing `FraudulentListing` variant and carries the precise
finding class in `chio.finding.challenge-outcome.v1`.

Consequently the listing integration does NOT extend
`GenericListingActorKind` (closed 4-variant enum,
`chio-listing/src/listing.rs:23`). Chosen shape, zero listing-schema changes:

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

One admission seam is real and must be built: `BondBacked` evaluation is
transient, `Listing` carries no activation proof, and `bid()` does not consult
that result. `require_bond_backing` currently pushes
`BondBackingRequired` and returns `admitted = false`
(`chio-listing/src/trust_activation.rs:558-572`). M2 therefore persists the
venue-signed admission bundle from F1 and makes trusted discovery, bid, and
M4 accept reverify it. Merely clearing a Boolean or presenting a signed bond
string would leave the marketplace bypass intact.

### 7.4 Conformance obligations

The conformance layers have different costs:

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
- **Finding-purchase corpus rotation** (expensive, gated): the
  `RequireFindingPurchase` marker with exact ids and settlement selector changes
  admission again at M4. Add a `finding_purchase` scenario class covering
  provider mint rejection when the marker is required but absent,
  malformed and unknown variants, exact request mismatch, alternate token,
  selected-grant ambiguity, buyer/payer-key mismatch, unauthorized seller or
  payee, stale/reused reservation, malformed/oversized purchase context,
  media mismatch, missing or extra escrow-witness context under either
  settlement mode, wrong settlement-profile digest, missing purchase
  artifacts under a marked grant, an unmarked generic digest call, and
  fail-closed portable behavior. Recompute
  the same manifest hashes, update the conformance documentation, and require
  every driver to emit the new tuples with the M4 change.
- **Economics/status/settlement corpora** (milestone-owned): M5 covers bond
  allocation reuse and concurrent exposure, buyer-challenge bond disposition,
  bondless venue-audit authorization, liability and purchase idempotency,
  beneficiary injection, pre-impairment appeal, committed audit selection,
  and separated fee-funded reimbursements. M6 covers
  cross-domain and ordinary-root rejection plus stale/omitted status. M7
  covers wrong or reorged escrow witnesses, settlement-release
  cross-binding, deadline bounds, release/refund replay, authority key
  rotation, root withholding, and response withholding.

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
there. Their JSON schemas and registry rows use
`spec/schemas/chio-wire/v1/receipt/`; tests validate typed round trips and
prove the enclosing `ChioReceipt` signature covers each block. They do not
enter the standalone signed-artifact allowlist.

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

- `POST /v1/findings/publish` - strict canonical Finding ingress plus
  transactional admission.
- `GET /v1/findings/{finding_id}` - immutable content-addressed resolution
  used by listing metadata URLs.
- `POST/GET /v1/findings/search` - size-bounded, paginated descriptor index
  over a length-bounded topic prefix plus exact `context_sha256`; precedent:
  the generic-listing search handler (`certification_handlers.rs:143`).
- `GET /v1/findings/status/{feed}/root` and
  `GET /v1/findings/status/{feed}/proof/{finding_id}` - epoch root and
  portable sparse (non-)inclusion proofs from the finding-status backend.
  The key shape is reusable (`RevocationKey{ subject_id, epoch_nonce }`,
  `SubjectId(String)`, `chio-revocation-oracle/src/api.rs:28,70`), but the
  signed root and proof types are new and domain-separated as required by
  4.4. HTTP is the pragmatic wedge transport; the federation gossip/iroh lanes
  (`chio-federation/src/revocation_gossip.rs`,
  `chio-federation-transport-iroh/src/lanes/revocation.rs`) are the
  cross-org distribution path later.
- Challenge submission and signed outcome publication extend the existing
  open-market penalty surfaces (`OPEN_MARKET_*` routes). Enforcement maps to
  the already-shipped `FraudulentListing` abuse class through the exact
  signed-outcome wrapper.

### 8.2 The scheduling gap (explicit)

There is NO in-repo job runtime: `AnchorAutomationJob` and the settle
watchdogs are cron-descriptor artifacts with `assess_*` verifiers, and
nothing in the workspace schedules them
(`chio-anchor/src/automation.rs:37`, `chio-settle/src/automation.rs:36`; no
scheduler dependency exists). Status-feed epoch ticking
(`tick_and_broadcast`, `chio-revocation-oracle/src/epoch.rs:116`) and
root anchoring therefore run under operator cron per runbook, exactly like
anchoring does today. M7's settlement watchdog is likewise an external
restart-safe worker. PLAN carries these as documented operational
dependencies, not hidden in-process scheduling.

### 8.3 CLI surface

New `Commands::Finding` family following the documented pattern (clap enum
in `cli/types/`, dispatch module registered in `cli/dispatch/mod.rs:1-60`,
`cmd_*` fns calling the control-plane client - end-to-end precedent:
`chio trust liability-market` from `cli/types/trust.rs:1099` through
`cli/dispatch/trust.rs:897` to `cli/trust/liability.rs:178`):

`chio finding publish` (F1), `search` (F2), `verify` (the M2
`FindingEvidenceVerifier` facet report), `buy` (F3 handshake + reveal),
`challenge` (F4), `status` (F5 proof fetch).

### 8.4 Release-process obligations (ship-dark first)

The bounded-release machinery gives the wedge a dark-ship path: the
`cognition-market-experimental` feature on each owning crate keeps the
surfaces out of the bounded operational profile
until qualified, then entries land in the bounded qualification matrix
(`cargo xtask qualify bounded-chio`,
`docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json`;
`docs/release/QUALIFICATION.md:36`). Before any release-facing claim:

- CLAIM_REGISTRY rows: approved claims for the market wording plus
  `audited_assumption` rows for the finding-status operator, seller tool
  server, bond/reservation/settlement authorities, and M7 neutral mediator -
  `docs/reference/CLAIM_REGISTRY.md`.
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
| `crates/economy/chio-finding` (NEW) | implemented at M1 | 4.1 artifact types, strict integrity verification, and pure validation; terms/profile/backing/admission, recipe/purchase inputs and records, replay/challenge/outcome/enforcement/audit, status, and M7 settlement types follow by owning milestone |
| `crates/economy/chio-listing` | extend | finding listing integration per 7.3; descriptor search; live collateral activation |
| `crates/economy/chio-open-market` | extend | provider constraint minting and exact handshake checks; live bond allocation/exposure; challenge evaluation and signed outcome; mapping into unchanged market-penalty v1; participation fees and audit selection |
| `crates/core/chio-core-types` | extend | additive `chio.delivery-contract.v1` (M3) and `chio.finding.delivery.v1` (M4) receipt metadata structs and key constants; two fail-closed `Constraint` vocabulary extensions under 7.3 |
| `crates/kernel/chio-kernel` | extend | single-grant digest enforcement; strict purchase/request/seller/payee/reservation binding; authoritative budget/liability reservation before pure accept and reveal-time hold/capture; delivery/status metadata; typed memory-write-to-delivery lineage |
| `crates/guards/chio-guards` | extend | injected synchronous `FindingRetractionResolver` and opt-in fail-closed quarantine rule in `MemoryGovernanceGuard` |
| `crates/platform/chio-store-sqlite` | extend | durable reservation/payer, purchase index, collateral exposure, challenge/liability/effect/appeal state, status outbox, settlement watchdog, and provenance/lineage state |
| `crates/observability/chio-lineage` | extend | typed write-to-finding-delivery relation and reverse-resolution query |
| `crates/trust/chio-revocation-oracle` | extend | versioned, domain-separated true sparse finding-status backend and portable proofs; reuse operator/anchor plumbing only |
| `crates/platform/chio-control-plane` | extend | finding publish/by-id/search/admission and status-feed surfaces per 8.1 |
| `crates/products/chio-cli` | extend | `chio finding publish/search/verify/buy/challenge/status` per 8.3 |
| `crates/economy/chio-settle` | extend (thin) | verify finding escrow/release authority receipts and adapt them to the existing settlement-anchor release input (F6) |
| `crates/trust/chio-attest-buyer` | extend (thin) | M2 `FindingEvidenceVerifier` facet profile |
| `crates/platform/chio-transaction-passport` | extend | M9 ClaimSet integration consuming signed Finding-verifier reports; unsigned verifier inputs remain non-authority attachments |
| `crates/tooling/chio-conformance` | extend | scenarios per 7.2/PLAN |
| `spec/PROTOCOL.md` | extend | finding family section under 6.4.x; explicit-gaps update |

## 10. Instance profiles

| Dimension | Wedge: verified fixes | Vision: R&D negative results |
|---|---|---|
| `outcome_class` | `verified_fix` | `null_result` |
| Guarantee class | `deterministic_replay` (replay recipe mandatory) | mostly `metered_attested`; replay only when re-runnable |
| Challenge lane | mechanical only for the committed deterministic recipe and verdict | `evidence_invalid` only; replication protocols are future work (open problem 2) |
| Buyer's ceiling input | buyer-local estimate for running the failing suite; authenticated quote is M8 | buyer-local experiment estimate, if available; else planner prior dominates |
| Descriptor privacy | low sensitivity (org-internal contexts) | high (existence of a dead end is signal); coarse topics + leakage budgets |
| Trust span | one operator or bilateral | cross-org from day one; separately qualified measured-runtime pressure (threat model O1) |
| Residual risk driver | challenge griefing tuning | honest-cost fabrication (S2) |
| New machinery needed beyond wedge | - | replication decision rules; richer descriptor taxonomy; cross-org status-feed governance |

## 11. Non-goals (restated)

No auction or order book; no PSI/zk-SNARK machinery; no new escrow contract;
no finding-content storage inside Chio; no autonomous adjudication beyond
replay-checkable rules; no permissionless federation semantics
(`spec/PROTOCOL.md` section 14 posture unchanged).
