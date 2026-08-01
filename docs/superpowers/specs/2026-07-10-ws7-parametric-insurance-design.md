# WS7 Design: Parametric insurance (receipt-observable triggers)

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (see 2026-07-10-agent-economy-program-design.md)
- Depends on: WS3 for SLA-breach trigger class; WS1/WS4 for payout execution;
  the 2026-07-12 FROST quorum substrate through Phase 3 plus the later WS7 action
  mapping before panel activation; external economic-state continuity before
  claim/payout activation; trigger and evidence contracts land independently
- Claim track: implementation (not insurer-of-record; signed intent and evidence only)
- Branch: chio/ws7-parametric-insurance off main

## Goal

Add a parametric coverage tier where payout eligibility is established by a
deterministic, recomputable predicate over receipt-observable events rather than
a human adjudicator: any holder of the declared corpus recomputes the same
verdict. Dispatch still requires fresh capability, policy, guard, and ladder
authority for the payout action. The tier also adds an opt-in n-of-m
adjudication panel that supersedes the single-signer adjudicator on contested
claims, parametric and non-parametric.

## Context

chio-market already ships bound liability coverage with receipt-verified
claims. `quote_and_bind` prices a premium and binds a `BoundPolicy`
(`crates/economy/chio-market/src/insurance_flow.rs:651`); `BoundPolicy::file_claim`
re-verifies each referenced receipt against the kernel signing key, fails closed
on any unresolved or tampered receipt, and caps the payout at the coverage limit
(`insurance_flow.rs:326`). The full claim chain is a signed-artifact lineage from
claim-package to adjudication (`crates/economy/chio-market/src/claim.rs`), then
payout-instruction to settlement-receipt
(`crates/economy/chio-market/src/settlement.rs`). Every adjudicator today is a
single signer: `LiabilityClaimAdjudicationArtifact.adjudicator` is one `String`
(`claim.rs:305`), and the payout instruction hard-requires a signed adjudication
whose payable amount it copies (`settlement.rs:93,115`; `lib.rs:81`). The credit
loss lifecycle defaults `external_claim_adjudication_supported = false`
(`crates/economy/chio-credit/src/risk_reports.rs:140,151`).
`BoundPolicy::file_claim` is stateless with respect to prior claims and submits
directly to the supplied settlement sink (`insurance_flow.rs:326-332,417-444`).
Its per-call coverage cap is therefore not an aggregate policy limit or a replay
guard. The parametric path cannot reuse that method as its persistence boundary.

Three receipt-observable event families already exist to trigger on:
guard-denial and allow decisions carried in receipts; drift severity in
`AutonomousDriftReport.drift_signals[].severity` where
`AutonomousDriftSeverity` is `Warning | Critical`
(`crates/economy/chio-autonomy/src/model.rs:141,502,515`); and settlement
failure via a signed reconciliation sidecar that digest-binds the immutable
financial receipt. Settlement status is not written back into the receipt
(`spec/PROTOCOL.md:944-947`). SLA-breach artifacts arrive from WS3. The ladder
already mandates FROST n-of-m for
`settle.commitment` (`spec/CHIO_LADDER.md:707-717`, quorum semantics at
`CHIO_LADDER.md:430-448`), the precedent this workstream follows for panel
decisions. Boundary language is fixed by `spec/PROTOCOL.md:2814-2829`
(bounded liability-market claim, not an insurer network) and the
payment-lifecycle dispute fields by `spec/PROTOCOL.md:1098-1130`.

## In scope

1. `ParametricPolicy` artifact: exact canonical bound-liability coverage
   identity and allocation, one typed trigger predicate, a policy-anchored
   evidence-corpus window cadence, and a payout schedule.
2. Four v1 trigger predicate classes: guard-denial-rate over a window,
   drift-severity threshold, settlement-failure count, and SLA-breach count
   (the last gated on WS3).
3. `TriggerEvaluation` artifact: policy digest, evidence-corpus manifest,
   evaluation window, checkpoint and contiguous-range completeness proof,
   verdict with magnitude, and evaluator signature; recomputable by any holder
   of that complete corpus.
4. Auto-claim assembly: a fired trigger builds a `ClaimEvidence` bundle
   (`insurance_flow.rs:466`) over the corpus using `ReceiptFingerprint`
   linkage (`insurance_flow.rs:77`) and files it without an adjudicator.
5. Policy-declared payout mode and eligibility semantics, plus payout intent
   bound to a fresh authorized capital-execution instruction and reconciliation
   sidecar, mirroring the existing payout-instruction pattern
   (`settlement.rs:89-275`). Aggregate legacy plus parametric reserved and
   reconciled payouts cannot exceed the one bound-coverage allocation, and
   schedule math rejects overflow. A policy or
   trigger signature alone never authorizes fund movement.
6. A durable claim and shared liability-coverage ledger with semantic trigger
   identity, aggregate bound-coverage reservation, unique payout-intent binding,
   and a versioned
   contest lifecycle. Duplicate or concurrent evaluation cannot reserve or pay
   the same coverage twice.
7. Opt-in FROST-authorized adjudication-panel artifacts and verification,
   superseding the
   single-signer adjudicator for non-parametric disputes and parametric contests
   only after the FROST and key-epoch prerequisite is live; single-adjudicator
   remains the default.
8. Two new ladder action classes: `parametric.trigger_payout` and
   `adjudication.panel_decision`, each with a declared governance mode.
9. JSON schemas under `spec/schemas/`, schema-id constants, and conformance
   coverage for every new artifact, including `spec/schemas/registry.json`,
   `spec/schemas/MANIFEST.sha256`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive
   fixtures, and unknown-schema negatives.

## Out of scope (explicit cuts)

- Fund custody or on-chain execution. The artifact layer emits signed payout
  intent plus reconciliation binding only; movement is bounded by WS1/WS4 and
  the contract freeze. No new Solidity surface.
- Discretionary underwriting inside the trigger. Predicates are declared in the
  policy and evaluated deterministically; no model inference at evaluation time.
- New predicate classes beyond the four v1 classes (for example latency
  percentiles or oracle-price bands).
- New cross-issuer roster federation, FROST implementation, or key ceremony.
  `main` has ladder semantics but no production Rust FROST verifier. Panel
  artifacts may land disabled, but activation is hard-blocked until a production
  verifier resolves a trusted roster and key epoch. Endorsements alone never
  satisfy the quorum action.
- Any breaking change to the existing bound-liability claim chain or its
  single-adjudicator default. The panel is additive and opt-in, and the payout
  v1 verifier remains unchanged. Panel authority is carried only by the strict
  payout-instruction v2 path described below.

## Design

The first implementation is a pure `parametric` module beside the existing
claim chain in `chio-market` (`#![forbid(unsafe_code)]`, no I/O, serde plus
deterministic validation), per program invariant 4. It reuses
`ReceiptFingerprint`, `ClaimEvidence`, and the capital-execution-instruction
types from chio-market and chio-credit. A separate crate is allowed only if
implementation discovery proves the existing home creates a dependency cycle or
unworkable feature boundary. All money is `MonetaryAmount` (invariant 2); the
legacy `CoverageLimit.amount_cents` shape (`insurance_flow.rs:188`) is not reused.

### Trigger predicates

A predicate is a deterministic function of the declared corpus and
policy-declared parameters (thresholds, window bounds, counts); the same corpus
yields the same fired flag and tagged `TriggerMagnitude`, whose value is either
a count or an integer basis-point rate. v1 classes:

- `GuardDenialRate { min_events, threshold_bps }`: over deny and allow
  decision receipts in the corpus, `magnitude = denials * 10_000 / total` basis
  points; fires when `total >= min_events` and `magnitude >= threshold_bps`.
  Load rejects `min_events = 0` or `threshold_bps > 10_000`; evaluation widens
  the checked numerator to `u128`, divides before checked conversion to `u64`,
  and never relies on wrapping or saturating multiplication.
- `DriftSeverity { min_critical }`: over `AutonomousDriftReport` artifacts
  (`model.rs:515`), `magnitude = count of drift_signals with severity == Critical`;
  fires when `magnitude >= min_critical`. Load rejects `min_critical = 0`.
- `SettlementFailureCount { min_failures }`: over signed settlement
  reconciliation sidecars whose `receipt_digest` resolves to a verified
  immutable financial receipt in the same corpus, `magnitude = count where the
  sidecar outcome is Failed`; fires when `magnitude >= min_failures`. Load
  rejects `min_failures = 0`.
- `SlaBreachCount { min_breaches }` (WS3-gated): over WS3 SLA-breach
  artifacts, `magnitude = breach count`; fires when `magnitude >= min_breaches`.
  Load rejects `min_breaches = 0`.

Before computing any predicate, the evaluator verifies a corpus manifest with
one `SourceRange` for every collection the predicate reads: receipt store,
reconciliation sidecars, drift reports, and, once enabled, SLA artifacts. Each
source range identifies its checkpoint, inclusive first and last sequence,
subject and time window, and an authenticated index-root or range proof. The
proof derives the expected member count from the committed source rather than
trusting a count supplied by the evaluator. It also proves both query boundaries:
the predecessor is before the subject/window lower bound and the successor is
after its upper bound, or the committed index proves that either boundary is an
end of collection. The checkpoint time must be at or after the evaluation cutoff
and within the policy's maximum source-staleness bound. Resolved members must
form exactly each proven range; duplicate, missing, extra, unverifiable, stale,
or out-of-window members make the corpus incomplete. An incomplete corpus yields
`Incomplete { reason }`, not `NotFired`, reports no magnitude, and cannot
authorize payout or deny coverage. `NotFired` is reserved for a complete
verified corpus whose predicate evaluates false.

The source contract is explicit rather than assumed. Phase 1 defines an
`EvidenceCorpusSource` snapshot interface returning a source kind, trusted
signer/domain, `anchor_epoch`, checkpoint root, checkpoint time, committed query
index root, and boundary-complete proof. Phase 2 adds or reuses append-only
checkpointed stores for reconciliation, drift, and SLA artifacts. Until a source
implements that interface and its root resolves through a trusted source registry,
predicates that read it return `Incomplete`; an embedded self-signed sidecar or
evaluator-supplied root is not a completeness proof.

### Artifacts and types (schema ids chio.parametric.<artifact>.v1)

- `chio.parametric.policy.v1` -> `ParametricPolicy`: `subject_key`, coverage
  `MonetaryAmount`, effective window, `window_anchor`, `window_seconds`,
  `max_checkpoint_lag_seconds`, `TriggerPredicate` (tagged enum above),
  `PayoutSchedule`, `PayoutMode`, the exact canonical
  `SignedLiabilityBoundCoverage` body and envelope digests, payer and beneficiary
  identities, a typed payout rail plus destination-account digest,
  funding-facility id, pre-action authority digest, and one
  `EvaluatorAuthorityRef { authority_id, key_id, key_epoch }`. Panels govern only
  contested adjudication, never trigger evaluation. Verification resolves the
  bound policy and facility through
  trusted local state, checks that coverage and parties match, and verifies that
  the policy signer was authorized for that payer and facility. The bound
  liability coverage is the sole aggregate economic allocation; the parametric
  policy cannot declare another independent coverage limit. The v1 beneficiary
  is not caller-selected: it MUST equal the insured subject resolved from the
  canonical bound-coverage lineage, specifically the bound risk-package
  `subject_key`, and verification derives and compares that identity rather than
  trusting the policy copy. A different beneficiary is unsupported in v1. Only
  a future schema with a typed, signed delegation bound to the coverage, insured
  subject, beneficiary, destination, facility, validity window, and delegating
  authority may relax this rule; v1 rejects such an override. For contestable
  mode it also names a contest-authority policy and expected FROST group key,
  epoch, and action domain resolved from trusted local state;
  a key embedded
  only by the policy is never a trust root. `PayoutMode` is either
  `Automatic`, which removes discretionary adjudication after a deterministic
  trigger but does not replace dispatch authority, or `Contestable {
  window_seconds, panel_election_ref }`, which prohibits dispatch until the
  durable contest window closes without a contest or a valid panel decision
  authorizes it. The authority-authenticated claim record stores
  `contest_opened_at` from the trusted runtime clock and computes
  `contest_deadline = contest_opened_at.checked_add(window_seconds)`; an
  evaluator-supplied timestamp or an old evaluation-window end cannot shorten
  the contest period. Overflow rejects. Load-time
  validation rejects zero `window_seconds` or `max_checkpoint_lag_seconds`, a
  zero or mixed-currency coverage, a schedule whose
  currency differs from coverage, an inverted effective window, or a
  contestable mode without a valid signed panel election and nonzero window.
- `chio.parametric.trigger-evaluation.v1` -> `TriggerEvaluation`: policy digest,
  a typed corpus manifest containing the per-source checkpoints, inclusive
  sequence ranges, expected counts, range proofs, receipt fingerprints, and
  digest-bound refs to reconciliation, drift, and SLA artifacts;
  the exact policy-derived `evaluation_window`; `verdict:
  Fired { magnitude } | NotFired | Incomplete { reason }`; and the evaluator
  signature via `SignedExportEnvelope`
  (`crates/core/chio-core-types/src/receipt/lineage.rs:407`).
- `chio.parametric.auto-claim.v1` -> `ParametricAutoClaim`: binds a Fired
  `TriggerEvaluation` to the assembled `ClaimEvidence` (`insurance_flow.rs:466`),
  proving the claim's `supporting_receipts` are exactly the corpus receipts. It
  carries the semantic `TriggerInstanceKeyV1` described below and derives both
  `trigger_instance_id` and `claim_id` from that key. The trigger-evaluation body
  and envelope digests remain bound evidence, but neither is claim identity.
- `chio.parametric.contest.v1` -> `ParametricContest`: binds `claim_id`,
  policy and evaluation body digests, a bounded reason code, canonical evidence
  refs, and the authorized contestant identity and signature. The trusted
  receipt time is recorded by the claim store, not supplied as deadline
  authority by the contestant.
- `chio.parametric.payout-intent.v1` -> `ParametricPayoutIntent`: binds the
  auto-claim, a `SignedCapitalExecutionInstruction` (action `TransferFunds`,
  source `FacilityCommitment`, unreconciled), and the schedule-computed
  `PayoutBindingV1` and `payout_amount`, exactly as
  `LiabilityClaimPayoutInstructionArtifact` does
  (`settlement.rs:89-186`). It may be issued only after the policy's automatic
  eligibility or contestable-release condition is verified and the payout
  action carries fresh capability, policy, guard, and ladder authority. A policy
  signature or trigger evaluation by itself is not payout authority.
- `chio.parametric.payout-receipt.v1` -> `ParametricPayoutReceipt`: reconciliation
  sidecar state (`Matched | AmountMismatch`) with exact observed outflow,
  digest-bound to the immutable
  payout instruction and execution evidence, mirroring
  `LiabilityClaimPayoutReceiptArtifact` (`settlement.rs:191-272`).

`TriggerInstanceKeyV1` contains the parametric-policy body digest, canonical
bound-coverage body digest, subject key, trigger-predicate body digest, canonical
window start and end, and canonical evidence-range digest. Each policy defines a
window anchor and cadence. The evaluator derives the one window index containing
the cutoff with checked integer arithmetic; a caller cannot select a subwindow,
overlapping window, or alternate boundary. The evidence-range digest covers the
sorted stable source identities, committed query-index identities, canonical
subject and window bounds, canonical inclusive sequence bounds, expected member
counts, and ordered selected-member roots. It excludes outer checkpoint ids and
roots, proof serialization, signatures, signer keys and key epochs, anchor epochs
and anchor-rotation metadata, evolving whole-index roots, checkpoint timestamps,
and source-prefix high-water or cutoff metadata. Those excluded fields remain
mandatory authenticated provenance and completeness inputs; any missing, stale,
or invalid value fails closed, but the values do not identify the semantic
trigger. A later append-only checkpoint, signature or key rotation, anchor
rotation, or higher prefix high-water that validly proves the same stable
source/index/subject/window/sequence/count/selected-root tuple therefore produces
the same range digest and claim id. Changing any retained tuple field produces a
different evidence range, while a different policy, predicate, or evidence range
cannot alias the same trigger instance.

```text
trigger_instance_id = SHA256(
  "chio.parametric.trigger-instance.v1\0" || RFC8785(TriggerInstanceKeyV1)
)
claim_id = SHA256(
  "chio.parametric.claim.id.v1\0" || RFC8785({ trigger_instance_id })
)
```

`PayoutBindingV1` contains `claim_id`, expected claim version and lifecycle
fence, coverage reservation id and version, payer/source id,
beneficiary/counterparty id equal to the v1 canonical insured subject, facility
id, rail profile,
destination-account digest, capital-instruction body digest, and exact
`MonetaryAmount`. Every field is derived from the verified policy, bound
coverage, facility, claim, and reservation. Before signing and again before
dispatch, the verifier requires the capital instruction's source,
counterparty, facility, rail destination, currency, and amount to equal this
binding byte for byte. Caller overrides, including a beneficiary override, are
rejected.

`TriggerMagnitude` is tagged as `Count { value }` or
`BasisPoints { value }`. Each predicate has exactly one declared magnitude
unit: guard-denial rate is basis points and the three count predicates are
counts. `PayoutSchedule` is `Fixed { amount }` or
`Linear { base, per_unit_minor, magnitude_unit }`. Load requires the linear
unit to equal the predicate's unit. `per_unit_minor` means minor currency units
per one event or per one basis point, with no implicit scaling. Payout is
`checked_add(base, checked_mul(per_unit_minor, magnitude.value))`, then checked
against remaining aggregate coverage as described below.
Either checked operation returning overflow is a typed evaluation error and
produces no claim or payout intent; a cap is never used to hide overflow. No
floats. The shared panel artifact
`chio.adjudication.panel-decision.v1` is defined below.

### Claim, contest, and aggregate-coverage state

`chio-market` owns a backend-neutral `ParametricClaimStore`; the SQLite
implementation shares one writer for claim, policy-coverage, contest, payout
intent, and audit-event staging/cache rows. The authoritative heads live in the
external multi-key `EconomicStateAnchor`. `ParametricClaimRecord` is authority-authenticated
store state keyed by the derived `claim_id`, with unique
`trigger_instance_id`, a checked row version and lifecycle fence,
schedule-computed amount, optional panel-authorized amount, trusted
opening/deadline times, contest and panel digests, payout-intent digest, and
state:

`Ready | ContestOpen | Contested | UncontestedReleased | PanelReleased |
PanelDenied | PayoutReserved | Submitted | Reconciled | ReservationReleased |
Incident`, plus the exact external continuity-head digest.

WS7 composes these transitions into the shared `EconomicStateBatchV1`; it does
not define another economic coordinator. The batch uses the existing
`chio.economy.resource-head.v1` resources for semantic triggers, claims, and
shared liability coverage and the existing `chio.economy.effect-slot.v1` for
payout effects.
`AdmissionOperation` and the shared economic continuity coordinator own durable
handoff, commit, startup recovery, and reconciliation. `ParametricClaimStore`
supplies consumer transition proofs and local staging/cache operations under the
process-fenced shared serving owner. It MUST NOT introduce a second durable
operation type, WS7-local continuity coordinator, independent rollback authority,
or parallel dispatch journal.

Creating an automatic claim stages `Ready`; a contestable claim stages
`ContestOpen` with `contest_opened_at` and checked `contest_deadline` from
the trusted runtime clock. One shared `EconomicStateBatchV1` creates the semantic
trigger-instance head and claim head before local finalization. An evaluation
with the same semantic trigger key
returns the existing record when its recomputed verdict and payout agree, even
if the proof envelope encoding differs. A different verdict, magnitude, amount,
or immutable binding for that trigger instance is a conflict and emits no second
claim.

`file_contest` resolves the policy's contest-authority rule, verifies the
signed `ParametricContest`, and before the deadline compare-and-swaps the exact
external `ContestOpen` head to `Contested`, then finalizes the contest and audit
event locally. At or after the deadline,
`release_uncontested` advances that same external state to
`UncontestedReleased`; it cannot succeed if a contest won the race. The
boundary is exact: contest receipt time must be less than the deadline, while
uncontested release requires time greater than or equal to it. A panel decision
binds the claim and contest digests and transitions only `Contested` to
`PanelReleased` or `PanelDenied`; it never rewrites an uncontested release.
For both payable outcomes, the claim record stores the exact award returned by
the shared `LiabilityClaimAdjudicationArtifact` validator as the
panel-authorized amount. `ClaimUpheld` requires a positive same-currency award
no greater than the filed schedule-computed amount; it does not imply a full
award. `PartialSettlement` requires a positive same-currency award strictly
less than that amount. `ProviderUpheld` stores no payable amount and transitions
to `PanelDenied`. This preserves the live single-adjudicator award semantics.

One shared `LiabilityCoverageLedger` row per canonical
`SignedLiabilityBoundCoverage` body digest stores the currency, aggregate
coverage limit, reserved units, reconciled-paid units, and version. Legacy filed
claims and parametric claims reserve through this same row and external coverage
head API.
Production activation of parametric claim processing and payout dispatch remains
disabled until the existing legacy filed-claim path commits reservations and
releases through that same ledger and external coverage head API. Artifact and
schema work may land disabled before that migration; a second ledger or a
policy-digest-only allocation is forbidden.
Payout-intent creation accepts only `Ready`, `UncontestedReleased`, or
`PanelReleased`.
It first builds the immutable payout request and persists one RFC-0003
`AdmissionOperation::Prepared { kind: GovernedEconomicMutation }` with exact
claim, coverage, beneficiary/destination, amount, target and request bindings.
Only then does it stage one local transaction over the claim and coverage versions,
recomputes the schedule amount, selects that amount for `Ready` and
`UncontestedReleased`, or requires and selects the persisted panel-authorized
amount for `PanelReleased`, then checked-adds
`reserved_units + reconciled_paid_units + payout_amount`, rejects above the
policy limit, inserts exactly one signed payout intent, increments reserved
coverage, stores the exact `PayoutBindingV1`, increments the lifecycle fence, and
prepares the claim for `PayoutReserved`. One shared `EconomicStateBatchV1`
atomically advances the semantic-trigger, claim, and shared coverage heads and
creates that exact prepared operation's `chio.economy.effect-slot.v1` as `Ready`,
followed by local finalization.
Identical replay is a
no-op; a different intent for the same claim conflicts. The intent is not
dispatchable unless this committed claim state and reservation verify.

Dispatch first persists the owning `AdmissionOperation::MutationSubmitted`
handoff state/version/fence, then one
shared `EconomicStateBatchV1` compare-and-swaps `PayoutReserved -> Submitted`
and the exact
effect slot `Ready -> DispatchCommitted` using the claim version, lifecycle
fence, reservation version, payout binding, operation id and target binding. Only
that CAS winner calls the settlement target. Reconciliation moves the exact
reserved amount to paid and the slot to `Completed` in one shared
`EconomicStateBatchV1` claim-plus-coverage transition only from canonical
execution evidence. A crash after
slot commit uses authenticated target status or qualified same-key idempotency;
otherwise the slot/claim become unknown/incident and remain reserved without
another call.
`PayoutReserved` or `Submitted` may move to `ReservationReleased` only
with a terminal `VerifiedNoEffectProof` bound to the operation, instruction,
rail, and reservation. Outcome unknown remains reserved and enters `Incident`.
`AmountMismatch` records the actual outflow, freezes the unmatched remainder and
claim, and requires incident resolution; it never releases or re-prices the
balance automatically. No retry, alternate evaluation, or second signature can
exceed the aggregate bound coverage or create a second intent for one trigger
instance.

### Auto-claim data flow

1. Evaluator resolves the policy signer, payer, facility, evaluator, and every
   source signer/root through trusted registries. It verifies every declared source checkpoint and contiguous-range
   proof, then resolves exactly those corpora through a
   `ReceiptEvidenceSource`-style
   trait (`insurance_flow.rs:152`), verifying signatures against the kernel key,
   and resolves reconciliation, drift, and SLA sidecars via signature checks
   against the trusted source key and domain, not merely each embedded key.
2. It emits `Incomplete` on any completeness or verification failure. Otherwise
   it computes the predicate and emits a signed `Fired` or `NotFired`
   `TriggerEvaluation`.
3. On `Fired`, it assembles a `ClaimEvidence` whose `supporting_receipts` are the
   corpus fingerprints, emits `ParametricAutoClaim`, and inserts or verifies the
   externally anchored semantic trigger-instance/claim heads through the shared
   `EconomicStateBatchV1`. It never calls stateless `BoundPolicy::file_claim` as
   the replay or aggregate-coverage boundary.
4. It verifies payout eligibility from the signed policy. `Automatic` creates a
   `Ready` claim. `Contestable` opens the trusted-clock contest through the same external head
   state and remains non-dispatchable until either the no-contest deadline CAS or
   a FROST-authorized panel decision releases it.
5. Fresh authority for `parametric.trigger_payout` is necessary but not
   sufficient. After its exact `AdmissionOperation::Prepared`, the external
   `EconomicStateBatchV1` claim/coverage transition reserves remaining bound
   coverage, records the unique `ParametricPayoutIntent` plus exact
   `PayoutBindingV1`, and creates its existing `chio.economy.effect-slot.v1` as
   `Ready`;
   only the later handoff CAS winner may dispatch.
6. WS1/WS4 execute the bound capital instruction; observed execution is recorded
   in the digest-bound `ParametricPayoutReceipt` sidecar and the external terminal
   `EconomicStateBatchV1` slot/claim/coverage transition reconciles the reserved
   coverage.

The automatic path does not enter discretionary adjudication because the policy
already fixes the deterministic eligibility rule. A contestable path enters the
panel chain only when contested. In both modes, trigger verification establishes
the predicate result, the signed policy establishes the schedule and mode, and a
fresh authorized action establishes payout authority.

### FROST-authorized adjudication panels

WS7 uses the shared 2026-07-12 FROST quorum substrate. It does not define a
private roster, count individual endorsements as authority, or claim that a
group signature reveals the participating subset. A signed
`chio.adjudication.panel-election.v1` rider binds the exact canonical bound
coverage body and envelope digests, eligible claim class, FROST authority scope,
group key id and epoch, the
`chio.frost.adjudication-panel-decision.v1` domain, validity window, and the
coverage authority that elected the panel. Parametric policies bind that exact
rider. Existing non-parametric coverage opts in only through the same rider;
otherwise its single-adjudicator behavior is unchanged.

`chio.adjudication.panel-decision.v1` is the canonical action body. It binds the
panel-election digest, bound coverage and parametric-policy digests, claim id,
expected claim version and lifecycle fence, contest digest, outcome, optional
`awarded_amount`, issued time, and validity. It is carried with one
`FrostAuthorizationV1`. `chio_federation::frost::verify_for_execution` resolves
the trusted active roster, group-key epoch and permanent completed authorization
slot and verifies the exact action-body
digest, authority scope, resource id, resource version, lifecycle fence, action
class, and domain. The claim store consumes the private
`VerifiedFrostAuthorization` by binding its external slot in the same external
claim-head batch that advances the exact `Contested` claim to `PanelReleased` or
`PanelDenied`, then finalizes locally. A second body
authorized for the same old fence cannot execute. Missing FROST Phase 3,
inactive epoch, wrong domain or scope, or a stale resource fence returns
`UnsupportedQuorum` or a typed denial and leaves the claim contested.

Optional participant receipts may provide attributable audit evidence, but they
are neither required for execution nor proof of the signer subset. Award
validation still matches `LiabilityClaimAdjudicationArtifact`: `ClaimUpheld`
requires an explicit positive same-currency amount no greater than the filed
amount, `ProviderUpheld` carries no payable amount, and `PartialSettlement`
requires a positive same-currency amount strictly below the filed amount. Every
payable result remains bounded by the shared coverage ledger.

The concrete `chio.market.claim-payout-instruction.v1` schema remains unchanged
because it embeds `SignedLiabilityClaimAdjudication`. Panel support adds strict
`chio.market.claim-payout-instruction.v2` with a tagged authority reference:
`SingleV1 { adjudication_envelope_digest }` or `FrostPanelV1 {
panel_election_digest, panel_decision_body_digest, frost_authorization_digest }`.
Version-first decoding rejects unknown or mismatched variants. A v1 instruction
cannot carry or silently ignore panel authority, and a v2-to-v1 conversion
rejects the FROST variant.

### Integration points

- Evaluation runs offline in the CLI and the `chio trust serve` comptroller
  plane, off the kernel dispatch path, like the rest of chio-market. The kernel
  contributes only the receipt corpus via its store.
- Persistence goes behind `platform/chio-store-sqlite` traits (invariant 4).
- Payout execution consumes the signed intent through the WS1 settlement hook /
  WS4 clearinghouse; the artifact layer never moves funds.
- Ladder: `parametric.trigger_payout` is `receipt_backed`, `destructive: true`,
  `co_sign: bilateral_required`; the policy signature fixes eligibility and
  payout mode, while dispatch still requires current action authority, mirroring
  `market.liability_auto_bind` (`CHIO_LADDER.md:696-705`).
  `adjudication.panel_decision` is `receipt_backed`,
  `destructive: true`, `co_sign: n_of_m`, `consistency_model: quorum-required`,
  `consistency_anchor: frost-quorum`, and
  `co_sign_quorum { n: 2, m: 3, scope: treaty }`, mirroring
  `settle.commitment`. Phase 3 registers that exact tuple and canonical ladder
  entry digest in the FROST mapping.

### Error handling (fail-closed)

- Any invalid checkpoint, range gap, count mismatch, unresolved member, or
  unverifiable corpus member yields `Incomplete`; no payout or denial follows
  from absence of proof.
- A `NotFired` verdict is path-isolated: it never denies a filed non-parametric
  claim and never populates the adjudication chain. The two paths stay distinct.
- Zero, mixed-currency, or off-currency coverage or schedule rejects at policy
  load (invariant 3); a corpus whose window or subject mismatches the policy
  rejects.
- Schedule overflow rejects with a typed error before the coverage cap and emits
  no payout intent.
- Duplicate semantic trigger, stale claim version or lifecycle fence,
  conflicting claim body, second payout intent, coverage-ledger currency
  mismatch, checked-sum overflow, or
  aggregate reserved-plus-paid amount above policy coverage rejects before
  dispatch. Outcome-unknown execution never releases reserved coverage.
- A contest with an unauthorized signer, wrong claim/evaluation digest, or
  trusted receipt time at or after the deadline rejects. A no-contest release
  before the deadline rejects. Concurrent contest and deadline release use the
  same expected version, so at most one transition commits.
- A panel decision with a missing or invalid FROST authorization, inactive group
  key epoch, wrong domain or authority scope, mismatched action digest, stale
  claim version, or stale lifecycle fence rejects.
- A panel outcome with absent, off-currency, zero, or over-limit award semantics
  rejects, and a payout amount must equal the shared adjudication validator's
  result for either authority variant. Single and panel `ClaimUpheld` cover both
  a full award and a smaller positive award, and the exact returned amount is
  persisted, reserved, and dispatched. `PartialSettlement` equal to the filed
  amount rejects, while a smaller positive amount follows that same exact-value
  path.
- A self-signed policy, unknown facility or source root, payer, v1 beneficiary
  differing from the canonical insured subject, destination, rail, reservation,
  currency, or amount mismatch, untrusted evaluator, absent FROST provider,
  stale key epoch, or roster/transcript mismatch rejects.

## Alternatives considered

1. Where the panel machinery lives. (A) Extend chio-governance case machinery
   with threshold endorsement: rejected. `GenericGovernanceCaseArtifact` is a
   single-`issued_by` artifact whose kinds are Dispute/Freeze/Sanction/Appeal
   (`crates/trust/chio-governance/src/generic.rs:17-22,209`), it lives in the
   trust layer not the economy layer, and adding n-of-m would couple insurance
   adjudication to registry governance. (B) A new shared adjudication module
   beside the existing claim chain in chio-market: recommended. It reuses the
   claim types and the `SignedExportEnvelope` pattern and serves both
   non-parametric disputes and parametric contests. (C) Reuse the FROST n-of-m
   quorum semantics from `CHIO_LADDER.md:430-448`: adopted as the ladder anchor
   and governance mode for (B) via `adjudication.panel_decision`, not as a
   separate artifact home. Recommendation: B, bound to C's quorum-required mode.

2. Where trigger evaluation runs. A kernel-side hook could fire triggers inline,
   but that adds business logic to the dispatch path (program invariant 4
   forbids it) and makes verdicts non-recomputable by third parties. Recommended:
   an offline deterministic evaluator over the receipt corpus, matching the
   economy-crate pattern and keeping verdicts independently recomputable.

3. Payout-intent shape. Reusing `LiabilityClaimPayoutInstructionArtifact` would
   force a fabricated adjudication, since it hard-requires a
   `SignedLiabilityClaimAdjudication` and copies its awarded amount
   (`settlement.rs:93,115`). Recommended: a sibling `chio.parametric.payout-intent.v1`
   authorized by the signed policy's declared payout mode after a Fired
   `TriggerEvaluation`, reusing its capital-instruction and reconciliation
   constraints.

## Claim and release framing

WS7 is implementation within the bounded release posture. The parametric tier
deterministically establishes eligibility and computes a policy-declared payout
schedule against verified receipt-observable triggers; it is not discretionary
underwriting or insurer-rate setting, and it does not itself authorize or execute
payment. Chio is not the insurer of record and this is not a regulated insurance
product: the boundary language of `spec/PROTOCOL.md:2814-2829` (a bounded
liability-market claim over canonical evidence, not an insurer network or
permissionless market) governs all external framing. A `TriggerEvaluation` is
signed intent plus recomputable evidence and does not upgrade its corpus receipts
from asserted to observed or verified (program invariant 1). Payout execution is
separately authorized through WS1/WS4 and bounded by the contract freeze; live
capital stays a separate track. Fail-closed holds both ways: no payout without
verifiable trigger evidence and fresh dispatch authority, and no coverage denial
derived from absent evidence.

## Testing strategy

- Determinism: a property test that the same corpus yields the same verdict and
  magnitude across runs and serialization round-trips.
- Fail-closed trigger: a tampered or missing corpus receipt, range gap, wrong
  checkpoint, duplicate sequence, or count mismatch yields `Incomplete` with no
  payout (mirroring `file_claim`, `insurance_flow.rs:1057-1139`), and that verdict
  produces no `ClaimDenialReason` and cannot deny a bound-liability claim.
- Settlement failure: immutable receipt plus valid reconciliation sidecar counts;
  mutation of receipt metadata, a dangling sidecar, or a digest mismatch rejects.
- Schedule integer math: fixed and linear schedules, checked and capped at
  aggregate remaining coverage, proptested over count and basis-point magnitudes
  including unit mismatch and overflow inputs; zero count thresholds and
  overflow reject without an intent.
- Claim idempotency and coverage: alternate evaluation-body encodings and
  concurrent evaluations for one semantic trigger create one claim and one
  payout intent. Changing policy, subject, canonical window, predicate, or
  evidence range changes the trigger key. Advancing an append-only checkpoint,
  whole-index root, signer key or epoch, anchor epoch, or prefix high-water while
  proving the identical stable source/index/subject/window/sequence/count and
  ordered selected-member-root tuple retains the same key; changing one retained
  field changes it. A file-backed concurrency test races a
  legacy filed claim with a parametric claim and proves their combined reserved
  plus paid value never exceeds the one canonical bound-coverage allocation. A
  terminal operation-bound `VerifiedNoEffectProof` releases once to
  `ReservationReleased` and advances the effect slot to `NoEffect`; an unknown
  outcome remains reserved.
- Anti-rollback: restore same-active-epoch claim/coverage SQLite snapshots after
  semantic-trigger creation, contest release/panel decision, payout reservation,
  submission, reconciliation and reservation release. Startup reconstructs the
  external trigger/claim/coverage heads or remains unready; it never creates a
  second claim, reuses reserved/paid coverage or redispatches from restored state.
- Effect slots: restore AdmissionOperation, claim and payout databases after the
  external payout slot commits but before local submission/result state. The
  target is never called again without qualified same-key idempotency; exact
  authenticated completed/no-effect status resolves and ambiguity remains locked.
  Slot creation without the exact prior prepared operation rejects.
- Payout modes: an automatic policy signature establishes deterministic
  eligibility but cannot emit a dispatchable intent without fresh capability,
  policy, guard, and ladder authority; a contestable policy additionally cannot
  emit one before the trusted deadline or a valid panel release. Boundary and
  race tests file a contest immediately before, exactly at, and after the
  deadline and concurrently run no-contest release; exactly one valid CAS wins.
- Panel award binding: payable upheld and partial outcomes persist the exact
  validator-returned award, while denied persists no amount. Both a full and a
  smaller positive `ClaimUpheld` award pass; `PartialSettlement` must be strictly
  smaller than the filed amount. Reservation and payout bytes must equal the
  persisted amount; mutating any one independently rejects.
- Payout binding: mutate payer/source, beneficiary/counterparty, facility, rail,
  destination account, instruction digest, claim or reservation version,
  currency, or amount independently and assert denial before dispatch. A
  beneficiary different from the canonical insured subject rejects even when all
  other fields match.
- Panel: official and Chio FROST vectors, wrong-domain/action/resource/fence
  negatives, and supersession of the single adjudicator only through a signed
  panel election plus `VerifiedFrostAuthorization` consumed in the claim CAS.
  Optional participation receipts do not authorize execution. With no FROST
  provider or an inactive key epoch, the action returns
  `UnsupportedQuorum` and remains non-authoritative. Upheld, provider-upheld, and
  partial awards share the existing currency, filed-amount, and coverage caps;
  both v2 payout-authority variants derive exactly the same payable amount. A v1
  instruction rejects panel fields, and lossy v2-to-v1 conversion rejects.
- Conformance: JSON schemas under `spec/schemas/`, canonical-JSON round-trips,
  and schema-id constants for every `chio.parametric.*` and
  `chio.adjudication.panel-election.v1`,
  `chio.adjudication.panel-decision.v1`, and
  `chio.market.claim-payout-instruction.v2` artifact.
- Ladder: manifest conformance proving both new action classes carry a governance
  mode and that `adjudication.panel_decision` is `quorum-required`.
- Signed-schema gates: every new signed family is present in the schema registry,
  hash manifest, and known-schema allowlist, with positive fixtures and
  unknown-schema negatives.

## Implementation phases

1. `chio-market::parametric` contract module: `ParametricPolicy`, complete-corpus
   manifest and verification, canonical policy-derived trigger windows,
   `TriggerInstanceKeyV1`, `TriggerEvaluation`, the three non-WS3 predicate
   classes, canonical insured-subject beneficiary and exact destination binding,
   checked `PayoutSchedule` evaluation, deterministic validation,
   schema constants, every signed-schema gate, and conformance. No payout
   execution. Extract a crate only if implementation discovery proves the
   existing home is unworkable. Lands independently of WS1/WS3/WS4.
2. Auto-claim and payout artifacts: `ParametricAutoClaim`,
   `ParametricContest`, `ParametricPayoutIntent`,
   `ParametricPayoutReceipt`, the corpus resolver trait, the backend-neutral
   claim/shared-liability-coverage contract, exact `PayoutBindingV1`, SQLite
   staging/cache implementation, composition into the existing
   `EconomicStateBatchV1`, resource-head, and effect-slot contracts, and
   concurrency/restore tests. It adds no second continuity coordinator or
   authoritative projection. This phase also moves the legacy filed-claim
   path onto the same coverage ledger; the legacy-plus-parametric race is a phase
   exit gate, and production activation of parametric claim processing and payout
   dispatch stays disabled until it passes. The phase also registers the
   `parametric.trigger_payout` ladder class.
3. Shared adjudication panel contract: signed
   `chio.adjudication.panel-election.v1`, canonical
   `chio.adjudication.panel-decision.v1`, strict
   `chio.market.claim-payout-instruction.v2`, the shared FROST verifier port, the
   `adjudication.panel_decision` ladder class plus enabled exact FROST mapping,
   and disabled wiring for parametric
   contests and non-parametric disputes. It cannot supersede the single signer
   or execute while FROST Phase 3 is absent.
4. Gated activation: after the external economic-state substrate is qualified,
   bind only externally reserved, exact-version/fence payout intents
   to the WS1/WS4 settlement surface,
   enable the `SlaBreachCount` predicate once WS3 lands, and activate panel
   supersession only after FROST Phase 3, the later exact action mapping and the
   external claim/coverage resource qualification
   pass. No endorsement-only fallback and no new on-chain surface.

## Resolved decisions

- The panel family is `chio.adjudication.panel-decision.v1`, matching
  `adjudication.panel_decision`. It is shared by parametric contests and
  non-parametric claim disputes, so it is not nested under the existing
  chio-market-only family.
- Discrepancy with the brief: drift severity is a per-signal field
  (`AutonomousDriftSignal.severity`, `model.rs:502`) inside
  `AutonomousDriftReport.drift_signals` (`model.rs:522`), not report-level; the
  `DriftSeverity` predicate reads signal-level severity accordingly.
- `SlaBreachCount` accepts only WS3's
  `chio.outcome.sla-breach.v1` canonical artifact through the trusted
  source/completeness contract. Unknown versions remain disabled.
