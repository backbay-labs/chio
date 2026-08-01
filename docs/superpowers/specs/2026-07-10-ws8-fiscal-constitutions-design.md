# WS8 Design: Fiscal constitutions (governed economic parameters)

- Date: 2026-07-10
- Program: agent-economy program, wave 1 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: none
- Claim track: implementation (parameters, not custody; not token issuance; not democratic governance claims)
- Branch: chio/ws8-fiscal-constitutions off main

## Goal

Make Chio's economic parameters a governed, charter-scoped signed-artifact
family with an amendment lifecycle, while guaranteeing that pricing and
penalties have deterministic bootstrap and recovery behavior without allowing a
broken update to bypass an activated charter. Today those parameters are
set three unrelated and ungoverned ways: hardcoded Rust constants,
operator-signed supersession artifacts, and config structs. WS8 unifies the
authority model without moving funds, issuing tokens, taking custody, or
claiming democratic governance. The honest trust model is m-of-n operator
signers plus a timelock.

## Context

Parameters live in code as constants: the credit-limit tier table
`MARKETPLACE_TIER_LIMIT_UNITS: [u64; 4]`
(`crates/economy/chio-underwriting/src/marketplace_limits.rs:41`, consumed by
`compute_marketplace_credit_limit` at line 82); the reputation-tier discount
curve `TIER_DISCOUNT_PER_HUNDRED: [u32; 4]`
(`crates/economy/chio-appraisal/src/marketplace_pricing.rs:148`, applied with
per-hundred integer math at lines 172-174); the premium basis-point schedules
in `premium_quote_for_outcome`
(`crates/economy/chio-underwriting/src/decision.rs:694`, tables at 700-712) and
the premium floors at `crates/economy/chio-underwriting/src/premium.rs:35-42`.

Parameters also live in operator-signed artifacts. `OpenMarketFeeScheduleArtifact`
(`crates/economy/chio-open-market/src/fee_schedule.rs:71`, schema constant at
line 10) carries `publication_fee`, `dispute_fee`, `market_participation_fee`,
and `bond_requirements` (lines 79-82) as a signed `SignedExportEnvelope`, scoped
to a namespace and one `governing_operator_id`, with no on-artifact supersession
lineage (a new schedule is re-issued with a later `issued_at`). The explicit
supersession precedent WS8 generalizes is the underwriting decision:
`UnderwritingDecisionArtifact` carries `supersedes_decision_id`
(`decision.rs:227`) and an `Active`/`Superseded` lifecycle
(`decision.rs:165-170`), and the store flips the predecessor only after
verifying it is currently `Active`
(`crates/platform/chio-store-sqlite/src/receipt_store/underwriting_credit.rs:34-99`).

Charters exist in `crates/trust/chio-governance/src/generic.rs`:
`GenericGovernanceCharterArtifact` (line 133, schema at line 12) declares an
authority scope and allowed case kinds but is single-operator (one
`governing_operator_id`, line 136) with no signer set or threshold; its cases
already model `supersedes_case_id` (line 208). WS8 reuses the charter concept
and generalizes the signer model to m-of-n. Signing is `SignedExportEnvelope<T>`
(`crates/core/chio-core-types/src/receipt/lineage.rs:407`), single-signer
(`sign` at 421, `verify_signature` at 431), so threshold approval is expressed
as independent approval envelopes from distinct charter members, not one
multi-signer object. Money is
`MonetaryAmount` (`crates/core/chio-core-types/src/capability/scope.rs:54`,
integer `units: u64` plus ISO currency). The central `ChioConfig`
(`crates/platform/chio-config/src/schema.rs:11`) has no economic fields, and no
`chio-fiscal` schema directory exists yet under `spec/schemas/`.

## In scope

1. A `FiscalDomain` enum over the governed parameter domains that actually exist
   at live consumers: tier limit tables, per-hundred marketplace discounts,
   decision-premium basis points, insurance-premium configuration, and the
   open-market fee and bond schedule. There is no invented penalty-rate domain.
2. Typed parameter payloads that preserve each live consumer's units and formula:
   `u64` minor units, integer basis points where the consumer uses basis points,
   per-hundred discounts where it uses per-hundred math, and finite `f64` only
   for existing insurance behavioral risk classification, never for a monetary
   coefficient or monetary operation.
3. A `FiscalCharter` artifact declaring the governed domains, an explicit
   signer set, and amendment rules (approval threshold, timelock, supersession
   lineage requirements), anchored by a pinned genesis authority and rotatable
   only under the currently active charter.
4. A `FiscalSchedule` artifact: a typed parameter set bound to its charter by
   digest, with a monotonic schedule sequence, explicit validity window, and
   supersession lineage.
5. Amendment lifecycle artifacts: `FiscalProposal`, an authority-authenticated
   `FiscalProposalAdmission`, `FiscalApproval` (per-signer), and
   `FiscalActivation` (aggregates m-of-n approvals, valid only after the
   admission-based timelock).
6. A pure resolver returning active or last-known-good governed parameters,
   bootstrap-only `Fallback`, or explicit `Denied`, plus consumption at the
   appraisal, underwriting, and open-market call sites.
7. Fail-closed verification for every transition, with bootstrap,
   last-known-good, and post-activation denial invariants tested at each call
   site.
8. A `fiscal.amendment_activate` action class proposed for
   `spec/CHIO_LADDER.md` 5.2 as a destructive, high-assurance action with its
   governance mode.
9. Signed-schema admission for every new signed family: schema registry, hash
   manifest, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive fixture,
   unknown-schema negative, and claim/proof manifest rows where public claims
   reference the family.

## Out of scope (explicit cuts)

- No treasury, currency issuance, custody, or value movement. Activation
  changes parameters; it never moves or holds funds.
- No token, no on-chain surface, no kernel-side business logic, and no change to
  the kernel metered-budget path or `FinancialReceiptMetadata`. WS8 lives in a
  pure contract crate plus store and comptroller-plane wiring, offline from the
  kernel dispatch path (shared invariant 4).
- No cross-federation parameter recognition. A charter governs one operator's
  own scope; treaty-level recognition of a peer's schedule is future work.
- No rewrite of the consumer pricing formulas. WS8 supplies the inputs; each
  consumer's arithmetic is unchanged apart from reading resolved parameters
  instead of the constant. The one required safety correction is fail-closed
  overflow: existing saturation to `u64::MAX` cannot become an authorized
  payable amount under program invariant 2. In-range outputs remain identical.

## Design

### Artifact family (schema ids `chio.fiscal.<artifact>.v1`)

All artifacts are canonical JSON (RFC 8785), signed as `SignedExportEnvelope`,
with schema-id constants and JSON schemas under `spec/schemas/chio-fiscal/`.
Each builder has a typed ID-preimage struct that omits the self ID and signature.
The ID is `sha256(canonical_json([domain_separator, id_preimage]))`; the final
body then includes that ID. Verification reconstructs the same preimage and
rejects a mismatch. Hashing a body that already contains its own ID is forbidden.
This follows the non-self-referential pattern of the existing builders
(`fee_schedule.rs:170`, `generic.rs:416`).

- `chio.fiscal.charter.v1` (`FiscalCharter`): `schema`, `charter_id`,
  `governing_operator_id`, `governed_domains: Vec<FiscalDomain>`,
  `signer_set: Vec<FiscalSigner>`, where `FiscalSigner { key_id, public_key }`,
  `approval_threshold: u32`,
  `timelock_seconds: u64`, `proposal_ttl_seconds: u64`,
  `approval_ttl_seconds: u64`, `issued_at`, required `expires_at`, `issued_by`,
  `sequence`, and optional
  `predecessor_charter_digest`. Its `chio.fiscal.charter.id.v1` preimage is
  every listed field except `charter_id`, with governed domains and signer keys
  in canonical sorted order by domain and `key_id`. `key_id` is the lowercase
  SHA-256 digest of the canonical public-key bytes and verification recomputes
  it. Builders sort and deduplicate both stored vectors and reject duplicate key
  ids or key bytes;
  strict decoding rejects an unsorted or duplicate stored body, so two wire
  bodies cannot share the normalized ID. Validation requires
  `approval_threshold in 1..=signer_set.len()`, a non-empty distinct signer set,
  non-empty governed domains, all three duration fields greater than zero,
  `proposal_ttl_seconds > timelock_seconds`,
  `expires_at > issued_at`,
  and coherent sequence/predecessor fields. Genesis acceptance also
  requires an operator-configured `FiscalGenesisPolicy` that pins the exact
  charter digest, bootstrap authority key, fiscal-anchor identity/namespace, and
  a canonical bounded `bootstrap_tier_limits` map from ISO-4217 currency to four
  nondecreasing legacy-parity unit ceilings. Its digest is part of the genesis
  policy. A non-genesis charter must be
  approved and activated under the currently pinned charter threshold; its new
  signer set cannot authorize itself.
- `chio.fiscal.schedule.v1` (`FiscalSchedule`): `schema`, `schedule_id`, `charter_id`,
  `charter_digest` (sha256 of the signed charter), `domain: FiscalDomain`,
  `params: FiscalParams`, `sequence: u64`, optional `supersedes_schedule_id`,
  `valid_from: u64`, required `valid_until: u64`, `issued_at`, `issued_by`.
  `FiscalParams` is an enum whose active variant must match `domain`. Its
  `chio.fiscal.schedule.id.v1` preimage is every listed field except
  `schedule_id`. Load requires `valid_until > valid_from`. The
  first schedule for a domain has `sequence = 1` and no supersedes id; every
  successor has `sequence = current.sequence + 1` with checked arithmetic and
  names the exact current active schedule id. A gap, duplicate sequence, or
  cross-domain predecessor rejects.

`FiscalParams` variants mirror the live consumers rather than combining
unrelated formulas:

- `TierLimits { ceilings: [MonetaryAmount; 4] }` replaces
  `MARKETPLACE_TIER_LIMIT_UNITS`. Load requires one nonempty ISO-4217 currency
  shared by all four entries and monotonically non-decreasing units. The
  `MarketplaceCreditLimitRequest` currency must equal that exact schedule
  currency; an unsupported or mismatched currency denies instead of borrowing a
  currencyless limit. `compute_marketplace_credit_limit` keeps its exact tier
  lookup and revocation-denial behavior and returns the selected
  `MonetaryAmount` unchanged.
- `MarketplaceDiscountPerHundred { discounts: [u32; 4] }` replaces
  `TIER_DISCOUNT_PER_HUNDRED` in its existing unit, with every value `<= 100`.
  Values are monotonically non-decreasing in the live tier order.
  `compute_marketplace_invocation_price` keeps
  `base.units * (100 - discount) / 100` with truncation and zero handling
  unchanged, but the governed adapter performs the multiply in checked `u128`
  and rejects a failed conversion instead of authorizing a saturated cap. For
  admitted `discount <= 100`, every valid in-range output is exactly the live
  output. Calling this value basis points would change the contract.
- `DecisionPremiumBasisPoints { approve: [u32; 4], reduce_ceiling: [u32; 4] }`
  replaces only the two tables in `premium_quote_for_outcome`. Risk-class order
  is `Baseline`, `Guarded`, `Elevated`, `Critical`; `StepUp` and `Deny` still
  produce no quote. `quote_premium_amount` retains
  `ceil(exposure.units * bps / 10_000)` over a widened checked intermediate.
  Both arrays are monotonically non-decreasing in risk-class order and each
  `reduce_ceiling[i] >= approve[i]`; a schedule that makes a riskier or more
  restrictive outcome cheaper rejects at load.
  Before fiscal activation, its return path becomes typed so conversion above
  `u64::MAX` denies the quote rather than saturating to a payable maximum.
- `InsurancePremiumSchedule { decline_floor, high_risk_floor,
  medium_risk_floor, low_risk_floor, score_adjustments_bps,
  behavioral_threshold, behavioral_penalty_per_sigma,
  behavioral_penalty_cap }` replaces the separate configuration consumed by
  `price_premium`. Monetary adjustment coefficients are fixed-point basis
  points: `score_adjustments_bps: [u32; 3]`, ordered low-, medium-, then
  high-risk band. The seed values are `[10_000, 20_000, 50_000]`, preserving
  the live 1x, 2x, and 5x additive adjustments. `behavioral_threshold: f64`
  remains a finite nonnegative risk-classification input, not a monetary
  coefficient; the remaining fields are `u32`. Load requires
  `decline_floor == high_risk_floor <= medium_risk_floor <= low_risk_floor <=
  1000`, and `score_adjustments_bps[low] <= score_adjustments_bps[medium] <=
  score_adjustments_bps[high]`. This prevents an accepted score from falling
  through to the live infinity fallback or receiving a lower premium at higher
  risk. The request
  still supplies compliance score, optional behavioral z-score, base-rate cents,
  and currency. Behavioral z-score math may remain finite `f64` because it only
  derives the bounded integer score band. Money math is exclusively checked
  integer arithmetic:
  `numerator = u128(base_rate_cents) * (10_000 + adjustment_bps)` and
  `quoted_cents = floor((numerator + 5_000) / 10_000)`, with every add,
  multiply, and conversion checked. This is nearest-cent, half-up rounding for
  nonnegative money and exactly matches the seed outputs. An overflow or
  out-of-`u64` result declines with a typed arithmetic reason rather than
  returning `u64::MAX`. After activation, callers cannot
  override the resolved schedule fields through `PremiumInputs`. The live
  `PremiumQuote.score_adjustment: f64` may be populated after the integer quote
  by converting the admitted basis points for display compatibility; that field
  is never read back into authorization or money math.

The exact legacy-parity domain for the insurance seed schedule is
`base_rate_cents <= 2^53`, where the integer-to-`f64` conversion is exact. For a
larger base, the live implementation can silently round an integer before the
multiplier even though the result remains within `u64`. Pre-activation hardening
returns typed `LegacyPrecisionUnsafe` for that range; post-activation governed
fixed-point math returns the checked integer result. This difference is an
intentional fail-closed precision correction, not a parity claim. Fixtures at
`2^53`, `2^53 + 1`, and the `u64` conversion boundary pin the behavior.
- `OpenMarketFeeAndBondSchedule { legacy_body:
  OpenMarketFeeScheduleArtifact }` carries the complete legacy body, including
  schema/id, scope, operator, three fees, ordered bond requirements, issuance and
  validity, issuer, and optional metadata. Fiscal validation requires
  `legacy_body.governing_operator_id == charter.governing_operator_id`,
  `legacy_body.issued_at == schedule.valid_from`, and
  `legacy_body.expires_at == schedule.valid_until`. The existing
  signed fee-schedule envelope and its namespace/operator/validity checks remain
  part of the evaluator contract.

There is no `PenaltyRates` variant. `OpenMarketPenaltyIssueRequest` supplies a
specific `MonetaryAmount`, and `evaluate_open_market_penalty` binds that signed
penalty to `fee_schedule_id`, requires matching currency, and caps its amount at
the selected bond requirement. Adding a separate rate table would invent a new
formula and a second authority instead of governing the live behavior.

### Amendment lifecycle

- `chio.fiscal.proposal.v1` (`FiscalProposal`): `schema`, `proposal_id`, a tagged
  `FiscalProposalTarget::{Schedule { candidate }, CharterRotation { successor }}`,
  a `rationale_digest` (sha256 of an out-of-band rationale document),
  `proposed_by`, and `proposed_at`. The
  `chio.fiscal.proposal.id.v1` preimage is every listed field except
  `proposal_id`. A successor charter must name the same
  governing scope, set `sequence = current.sequence + 1` with checked arithmetic,
  and bind `predecessor_charter_digest = current_charter_digest`; its signer set
  cannot authorize this proposal. `proposed_at` is signed provenance only, not
  the timelock clock. On admission, the durable store assigns a checked monotonic
  `admission_sequence` and trusted-clock `admitted_at`, then derives
  `admission_id` from the `chio.fiscal.proposal-admission.id.v1` preimage and
  binds it to the proposal digest, active charter digest, and charter sequence.
- `chio.fiscal.proposal-admission.v1` (`FiscalProposalAdmission`): a canonical
  body containing `schema`, `admission_id`, `proposal_id`, `proposal_digest`,
  `governing_operator_id`, `predecessor_charter_id`,
  `predecessor_charter_digest`, `predecessor_charter_sequence`,
  `admission_sequence`, `admitted_at`, `proposal_expires_at`,
  `admission_authority_id`, `signer_key_id`, and `signer_key_epoch`, signed by
  the configured durable-store admission authority. Its ID preimage contains
  every listed field except `admission_id`. `proposal_expires_at` must equal
  `admitted_at.checked_add(active_charter.proposal_ttl_seconds)` and may not
  exceed the active charter expiry or the candidate schedule/successor-charter
  expiry; overflow rejects. Admission also requires
  `activation_not_before < proposal_expires_at`. `admission_digest` is
  SHA-256 over the RFC 8785 canonical signed envelope and is stored with the
  exact envelope in `FiscalProposalAdmissionState`. The state is versioned and
  transitions by compare-and-swap from `Admitted` to `Activated`; a competing
  activation cannot consume it twice. `FiscalAdmissionTrustRegistry` resolves
  `(governing_operator_id, admission_authority_id, signer_key_id,
  signer_key_epoch)` from local configuration. No embedded or caller-supplied
  key is authoritative.
- `chio.fiscal.approval.v1` (`FiscalApproval`): `schema`, `approval_id`,
  `signer_key_id`, `proposal_id`, `proposal_digest`, `admission_id`,
  `admission_digest`, `approved_at`, `approval_expires_at`, each its
  own single-signer envelope whose signer key is a member of the active charter
  `signer_set`. The `chio.fiscal.approval.id.v1` preimage contains every listed
  body field except `approval_id`; verification recomputes it.
  `approval_expires_at` must equal
  `approved_at.checked_add(active_charter.approval_ttl_seconds)` and may not
  exceed `proposal_expires_at` or the charter expiry. Activation
  requires at least `approval_threshold` envelopes from
  distinct members; the total member count is `signer_set.len()`.
- `chio.fiscal.activation.v1` (`FiscalActivation`): `schema`, `activation_id`,
  `proposal_id`, `proposal_digest`, `admission_id`, `admission_digest`, current
  `charter_id` and digest, `approval_set_digest`, a tagged
  `FiscalActivationTarget::{Schedule { schedule_id,
  supersedes_schedule_id }, CharterRotation { successor_charter_digest,
  predecessor_charter_digest, successor_schedules }}`, the signed approval
  envelopes, the computed
  `activation_not_before = admitted_at.checked_add(timelock_seconds)`, and the
  activation time and issuer. Its `chio.fiscal.activation.id.v1` preimage
  contains every body field except `activation_id`. Approval envelopes are
  stored in ascending signer-key-id order with no duplicate signer or envelope
  digest. `approval_set_digest` is SHA-256 over the domain-separated RFC 8785
  list of those signer-key-id and canonical signed-envelope-digest pairs; a
  noncanonical order or duplicate rejects. The activation itself is signed and digest-binds the
  proposal, exact signed admission envelope and `admission_digest`, target
  artifact, current charter, and exact approval-set digest.
  It is valid only when every nested signature verifies, distinct signer keys
  reach `approval_threshold`, every signer is in the charter set, all approvals
  sign the same proposal digest, the candidate schedule is valid, and schedule
  and charter agree by digest. For `CharterRotation`, validation instead checks
  the successor's pinned governing scope, exact checked sequence increment, and
  predecessor digest, using the same authority-authenticated admitted proposal,
  current-charter approvals, and timelock before atomically pinning the
  successor. Because every active schedule binds the exact predecessor charter
  digest, `successor_schedules` must contain exactly one successor-charter-bound
  replacement for every domain whose `ever_activated` marker is true. Each
  replacement names the current active or last-known-good schedule in
  `supersedes_schedule_id`, increments its sequence exactly once, and preserves
  its params and validity bounds; parameter changes require a separate admitted
  amendment. Rotation validates all replacements and atomically pins the
  successor plus flips every affected domain. A missing, extra, changed, or
  invalid replacement rejects the entire rotation, so no domain loses its
  governed schedule between charters. Approval membership and threshold are always evaluated against the
  predecessor charter,
  never the successor.

Admission, approval, activation, rotation, and resolution all require
`verify_at < charter.expires_at`. Activation additionally requires
`verify_at < proposal_expires_at`, `verify_at < approval_expires_at` for every
counted approval, `admitted_at <= approved_at <= verify_at` for every counted
approval, and `candidate.valid_from <= verify_at <
candidate.valid_until`. An expired proposal, approval, charter, or candidate
cannot activate or rotate, even if its signatures and threshold remain valid.

All time fields are Unix seconds. Before evaluating the timelock or approvals,
activation resolves the admission authority from local trust, verifies the
admission signature and digest, and requires exact matches for proposal id and
digest, governing operator, predecessor charter id, digest, and sequence. It
also requires `admitted_at <= verify_at` and computes
`activation_not_before` only from that authenticated `admitted_at`. Activation
is verified against an injected trusted runtime clock and never trusted before
`activation_not_before`. The independent continuity checkpoint carries the
greatest successfully verified `verify_at`; a clock value below that high-water
mark denies activation and resolution. A resolver that observes a greater
trusted time must first advance that checkpoint by compare-and-swap before
returning a result. The store applies supersession the way the underwriting
store does: the named
predecessor must be currently active before it flips to superseded, keeping the
lineage a single unbroken chain. The same transaction compare-and-swaps the
admission from `Admitted` to `Activated` and records the activation digest,
activated sequence, staged active schedule, and last-known-good schedule. The
staged state is not authoritative or visible to consumers until the independent
continuity-anchor protocol below commits and the local row finalizes.

### Independent anti-rollback continuity

SQLite state is a cache and staging store, not proof that a domain was never
activated or that a trusted clock has not moved backward. Production activation
requires a configured `FiscalStateAnchor` outside the database backup and
restore domain. A remote append-only witness or a hardware-backed monotonic
store can implement the port. Another table, file, or database copied with the
same snapshot cannot. Missing, unavailable, unauthenticated, or non-monotonic
anchor state fails startup before serving fiscal resolution or mutation.

The anchor stores the latest signed
`chio.fiscal.continuity-checkpoint.v1` body for one governing operator. The
checkpoint binds:

- `anchor_id`, governing operator, monotonic `continuity_sequence`, and previous
  checkpoint digest;
- exact `FiscalGenesisPolicy` id and canonical body digest, including its
  bootstrap currency/limit map and anchor namespace;
- pinned charter id, digest, and sequence;
- the runtime-readiness registry digest;
- for every domain, `ever_activated`, active and last-known-good schedule ids,
  digests, and sequences;
- the trusted-clock high-water second; and
- any staged activation or rotation id and digest needed to finish recovery.

The anchor API provides an authenticated linearizable read and
`compare_and_swap(expected_checkpoint_digest,
VerifiedFiscalContinuityAdvance)`. Its
configured authority key and anchor identity are pinned locally, not accepted
from an activation request. The signing preimage is domain-separated canonical
JSON and excludes its own digest and signature. The anchor never accepts an
opaque signed successor.

`chio-governance` constructs `VerifiedFiscalContinuityAdvance` through a private
verifier. It requires the same anchor, namespace and governing operator; exact
`continuity_sequence + 1` and predecessor digest; nondecreasing trusted-clock
floor; exact unchanged v1 genesis-policy id/digest; `ever_activated` changing
only `false -> true`; and unchanged domain,
charter and readiness heads unless the advance carries the exact verified staged
activation, rotation or locally generated readiness artifact that authorizes the
change. Schedule and charter sequences advance exactly as their artifact rules
require, activated heads cannot disappear, and unrelated domain heads cannot
change. The anchor adapter rechecks this verified transition before CAS. A valid
signature over a rollback, skipped sequence, cleared activation bit, reduced
clock, unproved head swap or readiness downgrade rejects.

Activation and rotation use one recoverable three-step protocol:

1. In one SQLite `Immediate` transaction, validate the complete transition and
   readiness record, consume the proposal admission, and persist a `Staged`
   transition plus the exact next checkpoint body. Consumers still read the
   prior finalized state.
2. Compare-and-swap the independent anchor from the exact prior checkpoint to
   that next signed checkpoint. A conflict or unavailable anchor leaves the
   transition staged and serves no newer state.
3. In one SQLite transaction, require the exact anchored checkpoint, finalize
   the staged transition, and expose the new charter or schedules.

Recovery reads the anchor before trusting local authority state. If the anchor
contains the exact local staged checkpoint, recovery finishes step 3
idempotently. If the local database contains an unanchored staged successor,
recovery may retry step 2 or discard the stage while retaining the anchored
predecessor. If the anchor is ahead of the local database, the snapshot is
stale; startup fails closed and requires restoration of the missing signed
transition data. It never reconstructs `NeverActivated` from an older database.
If local finalized heads diverge from the anchor, startup also fails closed.

Bootstrap fallback requires an anchor-attested genesis checkpoint with
`continuity_sequence = 0`, the pinned bootstrap charter state, and
the exact configured `FiscalGenesisPolicy` id/body digest plus
`ever_activated = false` for the requested domain. The resolver constructs a
private `VerifiedFiscalGenesisPolicy` only when local canonical policy bytes equal
that checkpoint; caller or mutable unanchored config cannot supply fallback
limits. The v1 genesis-policy digest never changes after checkpoint zero. The
first activation anchors
`ever_activated = true`; no later checkpoint can clear it. Before returning any
resolution at a trusted time greater than the anchored clock high-water, the
resolver advances the checkpoint through the same CAS. Restoring SQLite alone
therefore cannot reopen fallback or roll the time boundary backward.

### Resolution and consumption

Consumers call one pure resolver only after startup reconciliation supplies the
authoritative `FiscalContinuityCheckpoint`, with `FiscalAuthorityState`,
the charter registry, signed schedules, signed proposals, exact signed proposal
admissions, signed activations and their embedded approvals, the locally
configured admission-authority registry, and persisted admission/domain state.
No `Governed` value exists without verifying the complete activation chain:
signed-schema admission; charter, schedule, proposal-admission, and activation
signatures; locally anchored admission authority; proposal/admission/predecessor
bindings; approval membership and uniqueness; threshold; approval-set digest;
authenticated timelock; validity window; monotonic sequence; admission state;
and supersession lineage.

`Fallback` is bootstrap-only. It is allowed only when the independently anchored
genesis checkpoint proves `BootstrapUnconfigured`, or when it binds a pinned
verified charter and proves that no schedule has ever been activated for that
domain. Omitting the anchor or charter, failing to load authority state, or
supplying an unpinned self-signed charter is `Denied`, not bootstrap. Once the
anchored `ever_activated` marker is true, the built-in constant cannot reappear.
A bad candidate update leaves the current verified,
in-window last-known-good schedule in force. If the active and last-known-good
schedules are expired, absent, or unverifiable, resolution returns `Denied` and
the consumer must not price, bind, charge, or penalize.

```rust
pub enum FiscalResolution<P> {
    Governed {
        schedule_id: String,
        sequence: u64,
        source: GovernedSource,
        params: P,
    },
    Fallback(FiscalFallbackReason),
    Denied(FiscalDenialReason),
}

pub enum GovernedSource {
    Active,
    LastKnownGood,
}

pub enum FiscalFallbackReason {
    AuthoritativeBootstrap,
    NeverActivated,
}

pub enum FiscalDenialReason {
    AnchorUnavailable,
    AnchorRollbackOrDivergence,
    ActivatedStateUnavailable,
    NoValidLastKnownGood,
    ClockRollback,
    VerificationFailed,
}

pub fn resolve_fiscal_schedule<P: FiscalDomainParams>(
    checkpoint: &VerifiedFiscalContinuityCheckpoint,
    authority: &FiscalAuthorityState,
    charters: &FiscalCharterRegistry,
    chain: &[SignedFiscalSchedule],
    proposals: &[SignedFiscalProposal],
    admissions: &FiscalProposalAdmissionRegistry,
    admission_trust: &FiscalAdmissionTrustRegistry,
    activations: &[SignedFiscalActivation],
    state: &FiscalDomainState,
    domain: FiscalDomain,
    verify_at: u64,
) -> FiscalResolution<P>;
```

Each consumer reads governed parameters, uses its exact built-in constant only
during bootstrap, or propagates denial. For the tier table:

```rust
let limits = match resolve_fiscal_schedule::<TierLimits>(
    continuity_checkpoint,
    authority,
    charters,
    chain,
    proposals,
    admissions,
    admission_trust,
    activations,
    state,
    FiscalDomain::TierLimits,
    now,
) {
    FiscalResolution::Governed { params, .. } => {
        require_same_currency(&params.ceilings, &request.currency)?;
        params.ceilings
    }
    FiscalResolution::Fallback(_) => bootstrap_limits_for_currency(
        verified_genesis_policy,
        &request.currency,
    )?,
    FiscalResolution::Denied(reason) => return Err(reason.into()),
};
```

The same shape wires five adapters: tier limits, marketplace per-hundred
discounts, decision-premium basis points, insurance-premium configuration, and
open-market fee/bond economics. Each adapter has exactly one active parameter
authority:

1. Before a domain's first activation, tier, discount, and both premium adapters
   use their exact current constants and request fields. Tier limits use only the
   genesis-policy currency map; an unlisted request currency denies. Open-market evaluation
   uses the currently trusted `SignedOpenMarketFeeSchedule`, because that live
   path has no built-in fee schedule.
2. The first activation stages `ever_activated`, the active fiscal schedule, and
   the adapter binding in one transaction, advances the independent continuity
   anchor by compare-and-swap, and then finalizes the local projection.
   Thereafter only verified
   `Governed`/last-known-good output may supply governed fields. A caller-provided
   discount, premium table, premium tuning value, or independently issued fee
   schedule cannot override it. Unavailable governed state is `Denied`, never a
   fall back to the old source.
3. The first open-market activation imports the exact canonical body and signed
   envelope digest of the currently trusted `SignedOpenMarketFeeSchedule` so the
   initial fiscal schedule is output-identical. The activation transaction
   stores a binding from the active fiscal schedule digest to that exact legacy
   envelope digest. Later amendments materialize a legacy compatibility envelope
   from the activated `OpenMarketFeeAndBondSchedule`, sign it with the locally
   trusted operator authority, and atomically store the same binding.
4. `OpenMarketPenaltyEvaluationRequest` continues to carry
   `SignedOpenMarketFeeSchedule` until that API is versioned. Its adapter accepts
   the envelope only when its signature is trusted, its digest equals the bound
   compatibility digest for the resolved fiscal schedule, and every scope, fee,
   bond, operator, and validity field equals the fiscal payload. The legacy
   envelope is then a compatibility projection, not a second authority.
   `SignedOpenMarketPenalty` remains case-specific and caller-amount-bearing; its
   existing fee-schedule id, currency, bond-cap, case, and signer checks are
   unchanged.
5. After first activation, the production control-plane fee-schedule issuance
   command accepts only an activated fiscal schedule and invokes the compatibility
   materializer in item 3. Direct production use of
   `build_open_market_fee_schedule_artifact` with caller-selected economics
   rejects as `GovernedExternally`; the pure builder remains available only for
   pre-activation compatibility and tests.
6. Penalty issuance, not only later evaluation, resolves the active fiscal
   schedule. The production adapter around
   `build_open_market_penalty_artifact_with_trusted_signers` requires the
   request's signed fee schedule to equal the active compatibility binding before
   it signs a penalty. Missing fiscal state, an independently issued schedule, or
   a stale bound digest denies issuance. This prevents a signed penalty from
   acquiring apparent authority under economics that activation already
   superseded.

The constant or legacy artifact remains the pre-activation source of truth, not
a post-activation recovery path. Migration parity is byte/output tested for all
valid inputs in each declared exact-parity domain before `ever_activated` is
committed. Insurance bases above `2^53` and overflow fixtures
must differ from legacy saturation by returning the new typed denial; they can
never be accepted as parity with `u64::MAX`.

### Integration points

- Reuse the existing `chio-governance` charter, proposal, approval, and
  activation lifecycle first, adding the minimum generic threshold and timelock
  support there. `chio-governance` also owns pure continuity-checkpoint and
  anchor-response verification. Keep typed economic payloads and consumer adapters beside their
  existing appraisal, underwriting, and open-market owners. Extract a pure
  `chio-fiscal` crate only if implementation discovery proves this arrangement
  creates a dependency cycle or unworkable feature boundary.
- Persistence behind traits in `platform/chio-store-sqlite`:
  `fiscal_authority_state`, `fiscal_charters`, `fiscal_proposal_admissions`, and
  `fiscal_schedules` tables with pinned genesis/current charter, the exact signed
  admission envelope/digest and CAS state, trusted admission time, legacy
  fee-schedule binding, staged transitions, exact checkpoint bodies, and
  active/superseded flips in atomic transactions. The control-plane composition
  root installs the independent `FiscalStateAnchor`; SQLite does not implement
  that port for production.
- Comptroller plane: propose, approve, activate, and resolve commands under the
  existing `chio trust serve` surface and CLI, offline from kernel dispatch.
- Consumers (`compute_marketplace_credit_limit`,
  `compute_marketplace_invocation_price`, `price_premium` /
  `premium_quote_for_outcome`, and open-market fee/penalty evaluation) call the
  resolver through five consumer-shaped adapters at their current call sites.
  No kernel-side logic is added.
- `spec/CHIO_LADDER.md` 5.2 gains `fiscal.amendment_activate`: mode
  `receipt_backed`, `destructive: true` because it can change credit, premiums,
  fees, and penalties, and a high-assurance authority floor. The charter's
  m-of-n independent approvals are the domain authorization check. The ladder
  class is private, `co_sign: none`, `consistency_model: totally-ordered`, and
  `consistency_anchor: external-checkpoint` over the continuity sequence,
  schedule heads, activation history, readiness digest, and clock high-water.
  It does not misuse ladder `n_of_m`, whose
  `quorum-required` semantics require a FROST implementation.

### Error handling (fail-closed)

A `FiscalError` enum separates three outcomes. An amendment can be rejected
(wrong charter, invalid nested signature, insufficient, duplicate, or non-member
approvals, unpinned or self-authorized charter, stale charter sequence, timelock
not elapsed, missing or untrusted admission authority, invalid admission
signature or digest, proposal/admission/predecessor mismatch, future admission
  time, expired proposal or approval, already-consumed admission, clock rollback,
  missing/unavailable/stale/divergent continuity anchor, lineage gap, schedule
  outside its validity window, unknown schema, schema mismatch, tier currency
  mismatch, consumer-unit mismatch,
  monetary arithmetic overflow, post-activation caller override, or
  unbound/mismatched legacy fee schedule), which leaves the
prior last-known-good schedule in force. Before the first activation, the
resolver can return `Fallback`. After the first activation, it returns a
verified in-window active or last-known-good schedule, or `Denied`; it never
silently restores built-in economics. Rejection and resolution are distinct
code paths so a bad amendment cannot replace trustworthy state.

## Alternatives considered

1. Extend the lifecycle primitives in `chio-governance` and keep fiscal payload
   adapters beside existing economy owners. Recommended first step: the signer
   set, threshold, proposal, approval, activation, and timelock semantics are
   generic governance concerns, while economy crates retain their domain types.
2. New pure crate `crates/economy/chio-fiscal` reusing `chio-governance`
   authority types. Deferred unless implementation discovery proves the
   reuse-first layout creates a dependency cycle or unworkable shared resolver
   boundary. A new crate is not justified by naming alone.
3. Put economic fields in `ChioConfig` / `chio.yaml`. Rejected: config is
   unsigned operator input, cannot carry m-of-n approval, timelock, or
   supersession lineage, and would violate the pre-action-authority and
   schema-discipline invariants.

## Claim and release framing

Implementation track within the bounded release posture. WS8 governs
parameters, not custody; it issues no token and settles nothing. The trust model
is m-of-n operator signers plus a timelock, and the design language must never
call this democratic governance or a vote. This is the first concrete economic
brick of the programmable-sovereignty ambition, which
`docs/papers/programmable-sovereignty/paper.tex` defers to after admission
semantics; WS8 stays parameters-only and imports none of that paper's formalism
or rhetoric. No public claim widens: a fiscal schedule is signed intent scoped
to one charter, and cross-federation recognition is future work.

## Testing strategy

- Artifact validation and builder determinism per schema (stable ids, canonical
  JSON round-trip), matching the existing economy-crate test style.
- Fail-closed rejection tests, one per error class: wrong charter digest,
  approvals below threshold, duplicate signer, non-member signer, timelock not
  elapsed, unpinned genesis, self-authorized rotation, stale charter sequence,
  missing authority state, missing admission, untrusted admission authority,
  invalid admission signature/digest, proposal or predecessor mismatch, future or
  already-consumed admission, lineage gap, schedule outside validity window,
  invalid first/next sequence, nonmonotonic discount or premium arrays,
  `reduce_ceiling < approve`, schema mismatch, parameter-unit mismatch, caller override, and unbound legacy
  fee-schedule digest.
- Bootstrap and recovery as the headline proof. For every domain and consumer
  call site, a parametrized test asserts that an anchor-attested genesis
  `BootstrapUnconfigured`, or a pinned verified charter with no prior domain
  activation, yields `Fallback` and exact built-in parity. Missing authority
  state, missing or unavailable anchor state, an omitted charter registry, or an
  unpinned charter yields `Denied`.
  After first activation, an invalid candidate, broken candidate lineage, or bad
  approval set preserves a verified in-window last-known-good schedule; an
  expired or unverifiable last-known-good state yields `Denied`, never
  `Fallback`. A property test asserts the resolver never returns `Governed` for
  an unverified, expired, wrong-charter, or unactivated schedule.
- Amendment lifecycle end to end: propose, approve to threshold, activate after
  the admission-based timelock, supersede the prior schedule, and confirm the
  store flip only succeeds against a currently-active predecessor and
  compare-and-swaps the signed admission to `Activated`. A backdated
  `proposed_at`, a caller-selected `admitted_at`, or an admission signed by an
  unregistered key cannot shorten the delay. Two concurrent activations for one
  admission have exactly one winner. Charter rotation requires the old
  threshold and cannot self-authorize a new signer set. Boundary tests cover the
  exact Unix-second deadline, checked-add overflow, and trusted-clock rollback.
- Anti-rollback crash matrix: crash before staging, after the local staged
  commit, after anchor CAS, and after local finalize. Recovery either retains the
  anchored predecessor or completes the exact anchored successor once. Restoring
  an older SQLite snapshot after first activation or clock advance fails startup
  and never returns `Fallback`; an anchor identity, signature, predecessor,
  sequence, genesis-policy id/body digest, readiness digest, or staged-transition
  mismatch also fails closed. Altering only the local bootstrap currency map
  cannot change a fallback result and denies when it no longer matches the
  checkpoint.
- Anchor semantic tests sign malicious successors that clear `ever_activated`,
  reduce clock high-water, skip sequence, swap an unrelated domain/head, remove
  an active head, change the genesis-policy id/body/currency map, or change
  readiness without its exact artifact; every CAS
  rejects before anchor mutation.
- Conformance coverage under `spec/schemas/chio-fiscal/` with insta snapshots
  using sorted maps for cross-environment key-order stability.
- Consumer parity tests assert the exact live formulas and units: per-hundred
  discount truncation, decision-premium basis-point ceiling, insurance
  behavioral rounding/cap plus checked fixed-point multiplier rounding, and open-market penalty
  currency/bond caps. Tier, discount, and both premium seed schedules match the
  current constants; insurance outputs match through `2^53`, while the
  `2^53 + 1` precision fixture is the declared typed correction. Decision and insurance premium
  overflow fixtures that currently saturate instead return a typed denial and no
  quote. Open-market migration imports the exact trusted
  legacy envelope, and post-activation evaluation rejects any independently
  issued or body-mismatched fee schedule. Post-activation direct fee-schedule
  issuance and penalty issuance against an unbound schedule both reject; the
  fiscal compatibility materializer and bound penalty issuance succeed. The
  workspace gate passes before any
  phase is declared done (shared invariant 9).
- Tier-limit tests require all four `MonetaryAmount` entries to share one
  ISO-4217 currency, reject request-currency mismatch, and preserve exact units
  for each tier. Bootstrap tests accept only currencies pinned in
  `FiscalGenesisPolicy` and reject an unlisted caller currency instead of
  attaching it to a currencyless constant. Charter, proposal, approval, and schedule boundary tests reject
  at their exact expiry second and prove no expired artifact can activate,
  rotate, resolve, or extend another artifact's lifetime.
- Activation-verifier tests mutate every nested proposal, schedule, approval,
  admission, activation, and charter binding and assert rejection. Charter
  rotation succeeds only with the exact successor-bound replacement set for all
  activated domains and preserves output parity; missing, extra, reordered,
  parameter-changing, or invalid replacements roll back the whole rotation.
  Approval/activation tests reject absent or unknown schemas, self-id mismatch,
  unsorted charter vectors or approval envelopes, duplicate signers, and a
  changed approval-set digest.
- Deployment-order tests prove Phase 3 cannot invoke `activate` or `rotate
  charter`, cannot set `ever_activated`, and cannot bypass any consumer. Phase 4
  enables mutation only after one atomic readiness transaction proves all five
  resolver adapters plus both open-market issuance gates are installed; any
  missing readiness bit denies without changing authority state. Restart with a
  prior activated database under a feature-disabled, partial, older, or
  digest-mismatched runtime adapter registry fails startup before serving.
- Signed-schema gates cover registry and hash-manifest membership,
  `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive fixtures, and unknown-schema
  negatives for every new family.

## Implementation phases

1. Reuse-first contract work: add generic threshold, Unix-second timelock, and
   activation verification to `chio-governance`; add the five exact
   consumer-shaped `FiscalDomain` and `FiscalParams` adapters beside their
   existing economy owners; harden both premium monetary conversions to typed
   overflow denial while retaining in-range formula/unit parity; land schemas,
   signed-schema gates, parity fixtures, and conformance. Extract a `chio-fiscal` crate only if a
   demonstrated dependency boundary requires it.
2. Amendment lifecycle artifacts (`FiscalProposal`,
   `FiscalProposalAdmission`, `FiscalApproval`, `FiscalActivation`) with local
   admission-authority resolution, pinned-genesis and current-charter rotation,
   required validity windows and TTLs, the signed
   `FiscalContinuityCheckpoint`, `FiscalStateAnchor` port, admission-clock
   fail-closed nested verification, and the pure
   resolver with `Governed`, bootstrap-only `Fallback`, last-known-good recovery,
   and `Denied`. Full unit and property tests remain offline.
3. Persistence in `chio-store-sqlite` (authority state, charter, exact signed
   admission/digest/CAS state, schedule, and legacy fee-schedule binding tables;
   atomic staging/finalization and pin/active/superseded/admission flips), an
   independent anchor adapter in the control-plane composition root, startup
   reconciliation, and offline or non-activating
   comptroller-plane commands (propose, admit, approve, resolve/preview) under
   `chio trust serve`. `activate`, `rotate charter`, and any transition of
   `ever_activated` remain unavailable in this phase.
4. Wire the five consumer adapters to resolve governed, bootstrap, or denied
   state, including the open-market legacy-envelope compatibility binding and
   post-activation fee-schedule and penalty issuance gates. Atomically persist a
   locally generated `FiscalConsumerReadiness` record only after the shared
   runtime assembler installs and self-tests all seven integration points. The
   record binds the build and schema version plus the canonical runtime adapter
   registry digest containing each adapter/gate id and implementation version;
   it cannot be supplied by an activation request. Startup recomputes that
   digest. If an activated database has a missing, mismatched, older, or
   rolled-back runtime registry/readiness version, startup fails before serving
   rather than trusting persisted bits. Require an authenticated independent
   anchor whose checkpoint matches that readiness digest, then expose `activate`
   and `rotate charter` through the staged-local, anchor-CAS, local-finalize
   protocol; add
   `fiscal.amendment_activate` to `spec/CHIO_LADDER.md` 5.2, and land the e2e
   test that a governed schedule changes a consumer output, pre-activation state
   has exact built-in parity, a rejected update retains last-known-good, and an
   unrecoverable post-activation state denies.

## Resolved decisions

WS8 retains the live per-hundred discount unit, keeps the two premium algorithms
as separate domains, uses fixed-point basis points for insurance monetary
adjustments while leaving finite behavioral risk classification in `f64`, and
treats the legacy open-market fee envelope as a bound compatibility projection.
