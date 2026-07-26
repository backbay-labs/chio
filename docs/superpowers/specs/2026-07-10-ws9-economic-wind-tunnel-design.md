# WS9 Design: Economic wind tunnel (adversarial economy arena)

- Date: 2026-07-10
- Program: agent-economy program, wave 3 (harness skeleton may land during wave 2; see `2026-07-10-agent-economy-program-design.md`)
- Depends on: attacks target wave-2 markets; WS8 parameters widen the attack surface
- Claim track: internal qualification (self-signed synthetic runs are not
  external evidence or underwriting facts)
- Branch: `chio/ws9-economic-wind-tunnel` off `main`

## Goal

The arena red-teams identity and capability security. It has no economic
adversaries. WS9 builds a deterministic economic wind tunnel: a suite of
seeded adversarial economic campaigns replayed against the real pure
economy validators, emitting signed pass/finding matrices. Each scenario
declares the fail-closed behavior an invariant should exhibit; a run that
observes a breach produces a finding routed like a bug, not a capability
claim. A signed matrix authenticates who asserted the declared harness, source,
binary, command, and corpus digests; the runner separately verifies those bytes
before signing. The self-signature does not independently prove what executed.
It is internal qualification output, not independent external evidence, not an
underwriting input, and not an insurance fact.

## Context

The existing arena is security-only. `AdversaryClass`
(`crates/core/chio-arena/src/adversary/mod.rs:53`) enumerates exactly four
classes (prompt-injection, capability-overrequest, replay-attempt,
scope-escape), and the `Adversary` trait
(`crates/core/chio-arena/src/adversary/mod.rs:114`) is a per-step, pure
transformation of one `ScenarioStep` into one expected `ScenarioVerdict`
(allow/deny/rewrite), refereed by the kernel-and-guard pool. The curated
`chio-adversarial-suite` corpus is likewise security-only: `ATTACK_CLASSES`
(`crates/core/chio-adversarial-suite/src/lib.rs:24`) covers clock-rewound,
replayed-nonce, scope-superset, and similar identity attacks. No class
touches pricing, credit, oracles, fees, or settlement liveness.

What the arena does provide, and WS9 reuses, is a determinism substrate: a
seeded ChaCha20 PRNG and a fixed virtual clock (the determinism contract at
`crates/core/chio-arena/src/adversary/mod.rs:21` forbids wall-clock, thread
local, and network reads; two runs are byte-identical), a canonical-JSON
replay-bundle writer (`crates/core/chio-arena/src/promote.rs:149`, schema
`chio.arena.bundle/v1`, `sha256_hex` over canonical bytes), and a
determinism gate (`crates/core/chio-arena/tests/determinism_gate.rs`).

The economic invariants WS9 attacks already exist as pure validators (each
is one scenario class; Adversary suite tabulates targets and findings):

- Sybil tier gate. `qualifies_for_tier_3`
  (`crates/trust/chio-reputation/src/tier.rs:135`) requires composed score
  >= 0.90 AND every feed >= 0.80 AND >= 2 distinct feeds; a single-feed
  flood stays at tier_2 (`tier.rs:96`). Marketplace credit limits derive
  from `compute_marketplace_credit_limit`
  (`crates/economy/chio-underwriting/src/marketplace_limits.rs:82`).
- Open-market bidding. `bid` / `accept`
  (`crates/economy/chio-open-market/src/bidding.rs:308`, `bidding.rs:439`)
  fail closed on authority mismatch (`bidding.rs:341`), sub-ceiling bids
  (`bidding.rs:369`), out-of-scope requests (`bidding.rs:376`), and
  reservations that do not cover total liability (`bidding.rs:480`,
  `token_offer_total_liability` at `bidding.rs:512`).
- Credit exposure and underwriting. `MAX_EXPOSURE_LEDGER_*`
  (`crates/economy/chio-credit/src/lib.rs:83`) bounds query result sizes, not
  admitted exposure. The backtest surfaces over-utilization after the fact
  (`crates/economy/chio-credit/src/risk_reports.rs:401`,
  `risk_reports.rs:442`), and the underwriting fuzz target checks tier ceilings
  and revocation inputs (`fuzz/fuzz_targets/underwriting_policy_input.rs:16`).
  None is evidence of an atomic new-exposure admission boundary.
- Oracle circuit breaker. `ensure_within_threshold`
  (`crates/economy/chio-link/src/circuit_breaker.rs:49`) trips
  `CircuitBreakerTripped` when integer `divergence_bps`
  (`circuit_breaker.rs:19`) exceeds the threshold; `ExchangeRate` carries
  `max_age_seconds` for staleness.
- Fee thresholds. `Constraint::RequireApprovalAbove { threshold_units }`
  (`crates/core/chio-core-types/src/capability/scope.rs:300`) gates a
  single request at or above the threshold.
- Settlement liveness. `classify_attempt`
  (`crates/economy/chio-settle/src/retry.rs:123`) bounds retries at
  `DEFAULT_MAX_RETRIES` (`retry.rs:30`), short-circuits permanent outcomes
  (`retry.rs:135`), and converges to `DeadLetter` on exhaustion
  (`retry.rs:139`).

The output artifact follows the autonomy qualification matrix:
`AutonomousQualificationMatrix` / `AutonomousQualificationCase`
(`crates/economy/chio-autonomy/src/model.rs:532`) with outcomes
`Pass | FailClosed` (`model.rs:174`), validated by
`validate_autonomous_qualification_matrix`
(`crates/economy/chio-autonomy/src/validation.rs:794`). Signing uses
`SignedExportEnvelope` (`crates/core/chio-core-types/src/receipt/lineage.rs:407`).

## In scope

1. Reuse existing unit, property, fuzz, conformance, and arena determinism tests
   to establish one honest production-validator target per scenario before
   adding a harness abstraction. Add only the smallest shared test helper needed
   for seeded multi-step campaigns; create a new crate only if the existing test
   homes prove unworkable.
2. Six v1 scenario classes, each declaring its target validator, its
   expected fail-closed behavior, and its finding condition:
   `sybil-pricing-ring`, `collusion-bid-ring`, `credit-exhaustion`,
   `oracle-divergence`, `fee-structuring`, `settlement-dos`.
3. `chio.econsim.scenario-result.v1` and
   `chio.econsim.qualification-matrix.v1` schemas under
   `spec/schemas/chio-econsim/v1/`, with schema-id constants and
   conformance coverage. If the matrix remains signed, it also lands in the
   schema registry, hash manifest, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive
   fixtures, and unknown-schema negatives.
4. A thin driver (a `chio econsim` CLI subcommand or an xtask) that loads
   corpora from disk, runs the engine, signs the matrix, and writes the
   bundle. Disk and key access live only here, never in the pure test helpers
   or any later extracted crate.
5. An advisory (non-blocking) CI facet under `ci-gates/`, following the
   fail-closed enumerated-manifest pattern of `ci-gates/runtime.toml`,
   promotable to blocking per scenario class. The facet may be advisory to
   unrelated changes, but its command exits nonzero for any unresolved High or
   Critical finding or a scenario with no valid production target.
6. Economic negative tests added to `chio-conformance` asserting the exact
   fail-closed error for each class, alongside the existing budget-split
   tests (`crates/tooling/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs:88`,
   `budget_split_cross_hop_rejects_amplification.rs:92`).

## Out of scope (explicit cuts)

- No changes to the economy validators. WS9 only replays them. Any breach
  is filed as a finding against the owning workstream, not patched here.
- No extension of the arena `Adversary` trait or `chio-adversarial-suite`
  with economic classes (see Alternatives). The arena substrate is reused,
  its per-step verdict model is not.
- No live money, no chain broadcast, no wall-clock. Corpora are synthetic.
  The contract freeze (`2026-07-10-agent-economy-program-design.md:115`)
  is untouched.
- No new capability claim; passing matrices evidence fail-closed behavior on
  the tested corpora, nothing broader.
- No external-evidence or underwriting role. Self-signing authenticates who
  made the run assertion and binds the declared byte digests; it does not prove
  that those bytes executed, supplies no independent observation, and cannot
  change an underwriting evidence class.
- No on-chain settlement DoS modeling; `settlement-dos` targets the pure
  retry classifier, not a network.

## Design

### Adversary suite

Each scenario class is a deterministic campaign: a seeded sequence of
synthetic economic actions applied to a corpus, replayed against one real
validator, yielding an observed disposition compared to the declared
expectation. Unlike the arena's single-step `AdversaryAction`, economic
campaigns are multi-step and accumulate state, so the engine models a
campaign as an action sequence over a running integer ledger.

| Class | Production target | Qualifying assertion | Explicit limit |
|-------|-------------------|----------------------|----------------|
| `sybil-pricing-ring` | `qualifies_for_tier_3` (`tier.rs:135`) and `compute_marketplace_credit_limit` (`marketplace_limits.rs:82`) | a single-feed flood cannot reach tier 3, and the same identity receives the limit for its resulting tier | these functions do not detect coordinated identities or cap aggregate ring credit; the matrix cannot claim they do |
| `collusion-bid-ring` | `bid` / `accept` (`bidding.rs:308`, `bidding.rs:439`) | authority, scope, price floor, and reservation-liability checks reject exact malformed bids | these validators enforce transaction integrity, not collusion detection; the class name does not widen the assertion |
| `credit-exhaustion` | no production admission validator identified | `TargetMissing` until a function that atomically compares current open exposure with the applicable facility or tier ceiling is named | `MAX_EXPOSURE_LEDGER_*` at `chio-credit/src/lib.rs:83` bounds query results, and the backtest reports over-utilization after the fact; neither prevents new exposure |
| `oracle-divergence` | `ensure_within_threshold` (`circuit_breaker.rs:49`), `ExchangeRate::ensure_fresh` (`chio-link/src/lib.rs:104`), and the actual conversion verifier | over-threshold divergence, stale rates, and conversion without required signed evidence each reject at their named boundary | one function does not establish all three properties; the case records each invoked target separately |
| `fee-structuring` | no cumulative-spend admission validator identified; `RequireApprovalAbove` (`scope.rs:300`) is per request | `TargetMissing` until an accumulator-bound validator consumes prior approved spend | a sequence of sub-threshold calls cannot be qualified by repeatedly invoking a per-request constraint |
| `settlement-dos` | `classify_attempt` (`retry.rs:123`) | one receipt's retry sequence reaches `DeadLetter` at the configured bound and computed backoff remains capped | the pure classifier does not bound queue size, duplicate dead letters, worker throughput, or adversarial volume |

A scenario can be `Held` only for the assertion implemented by its named
production target. `credit-exhaustion` and `fee-structuring` begin as
`TargetMissing` High findings rather than simulated passes. The narrower sybil,
bid, oracle, and retry cases must retain their explicit limits in the result so
the class label cannot imply a broader control.

The missing controls have named owners outside WS9:

- `AE-CREDIT-ADMISSION-1`, owned by `chio-credit` plus the WS1 canonical
  obligation store, must atomically compare current outstanding and reserved
  facility exposure plus the proposed amount against the applicable signed
  facility/tier ceiling before a new obligation can commit.
- `AE-CUMULATIVE-APPROVAL-1`, owned by `chio-kernel` budget/governed-intent
  admission, must consume an authority-bound cumulative approved-spend ledger so
  a sequence of sub-threshold calls cannot bypass `RequireApprovalAbove`.

Both controls use the contracts below and require implementation, concurrency
tests, and owning-crate review. WS9 only diagnoses and reruns them. They are hard
Wave 3 entry dependencies, not late exit checks; a scheduled matrix, waiver, or
advisory facet cannot substitute.

### Required production control contracts

`AE-CREDIT-ADMISSION-1` is a participant in the shared `AdmissionOperation`,
owned by `chio_credit::obligation` with its durable implementation in the WS1
`chio-store-sqlite` obligation store:

```rust
pub struct CreditExposureReservationRequest {
    pub operation_id: String,
    pub obligation_id: String,
    pub debtor_id: String,
    pub amount: MonetaryAmount,
    pub authorities: VerifiedCreditAuthoritySet,
}

pub trait CreditAdmissionStore {
    fn reserve_exposure(
        &self,
        request: &CreditExposureReservationRequest,
    ) -> Result<CreditExposureReservation, CreditAdmissionError>;

    fn lookup_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<CreditExposureReservation>, CreditAdmissionError>;

    fn release_before_dispatch(
        &self,
        operation_id: &str,
        proof: &VerifiedNoEffectProof,
    ) -> Result<(), CreditAdmissionError>;
}
```

`VerifiedCreditAuthoritySet` has a private constructor. The configured credit
resolver enumerates every applicable signed v1 facility and capability ceiling
for the authenticated debtor, scope and currency, rejects an incomplete or
conflicting set, and sets `effective_ceiling` to the minimum. WS8 tier adoption
is not an active program edge and is not a v1 authority source. A caller cannot
select one favorable reference or omit a stricter authority.

An authoritative `(debtor_id, scope_digest, currency)` account stores open units,
reserved units, the complete authority-set digest and epochs, and row version.
One `Immediate` transaction re-resolves that set, verifies debtor, scope,
currency and expiry, and checked-adds
`open_units + reserved_units + proposed.units <= effective_ceiling.units`.
Reservations are unique by `operation_id` and transition `Reserved -> Committed
| ReleasedBeforeDispatch | OutcomeUnknown`. The admission receipt projection
atomically moves `Reserved -> Committed` with the canonical obligation. Only a
pre-dispatch `VerifiedNoEffectProof` can release; post-dispatch ambiguity remains counted.
Settlement, authority supersession, and new admission compare-and-swap the same
account version, so derived exposure reports are never admission truth.

`AE-CUMULATIVE-APPROVAL-1` is owned by protocol-primitives and the kernel's
existing composite `BudgetStore` hold. Its versioned signed constraint is:

```rust
RequireCumulativeApprovalAbove {
    threshold: MonetaryAmount,
    approval_budget_id: String,
    approval_budget_epoch: u64,
    cumulative_approval_root_binding: Option<CumulativeApprovalRootBinding>,
}
```

The existing `RequireApprovalAbove { threshold_units }` constraint remains
per-request only. It is not accepted as cumulative approval authority and does
not participate in the cumulative account.

The authority-derived account key binds the authenticated constraint issuer and
family owner, signed budget id and epoch, root grant identity, and currency. A
delegated capability requires the byte-preserved CA-signed
`CumulativeApprovalRootBinding`; a nondelegable capability requires no family
binding. Sibling grants therefore cannot reset the accumulator, and delegation
without the binding rejects. The account stores
`reserved_authorized_units`, monotonic `captured_authorized_units`, the immutable
root authority threshold, and version. Each operation reservation stores the
verified effective leaf threshold. A descendant may lower that effective
threshold without changing the shared account or silently tightening a sibling.
In the same transaction that reserves the composite hold, the store checks the
prospective cumulative total against that operation's effective threshold. At or
above it the store always records `PendingApproval` under the already persisted
operation. A separate verified-approval compare-and-swap advances that same
reservation to `Authorized` without repeating authorization, so concurrent
sub-threshold requests cannot both pass.

The operation-owned state is `PendingApproval -> Authorized -> Captured |
ReversedBeforeDispatch`. The threshold proposal hash is derived from the durable
`PendingApproval` result and compare-and-swap attached once; the verified
approval set then attaches to the existing operation and reservation once. Both
are excluded from immutable operation identity. Capture never decrements cumulative authorized units. Reversal is
allowed only before dispatch with `VerifiedNoEffectProof`; committed approvals remain
replay tombstones. Missing or stale budget authority, currency mismatch, epoch
change, unavailable storage, or arithmetic overflow denies.

Required race tests cover concurrent 60+60 against a 100-unit ceiling,
settlement versus admission, facility or capability supersession versus
admission, omission of a stricter applicable authority, cross-debtor isolation, sibling
delegation aggregation, concurrent sub-threshold calls, approval attachment
versus timeout, restart in `PendingApproval`, and top-level/nested evaluator
parity.

### Simulation harness (deterministic)

The engine is a pure function of (seed, scenario class, class parameters,
corpus), reusing the arena determinism primitives: a ChaCha20 PRNG from a
recorded `u64` seed and a fixed virtual clock, under the arena contract at
`crates/core/chio-arena/src/adversary/mod.rs:21`. All money is integer:
`MonetaryAmount` u64 minor units, basis points, integer rationals;
checked arithmetic fails closed on overflow and never wraps
(`2026-07-10-agent-economy-program-design.md:94`). Reputation tier scores
stay f64 because they are risk coefficients, not money, and run through the
real gate unchanged. Corpora are synthetic receipt and exposure records
addressed by a canonical-JSON manifest digest (`sha256_hex` over RFC-8785
bytes, as `promote.rs:149` does). Where a validator verifies signatures
(the bid flow at `bidding.rs:313`) the corpus carries test-key signatures;
otherwise the campaign targets the post-verification surface. The engine
owns no clock or storage, matching the pure-function discipline of
`retry.rs:5`.

### Artifacts and outputs (schema ids `chio.econsim.<artifact>.v1`)

- `chio.econsim.scenario-result.v1`. One campaign outcome. Fields:
  `schema`, `scenario_id` (class plus population), `seed` (u64),
  `corpus_manifest_digest` (sha256 hex), `requirement_ids` (spec and
  invariant anchors the class defends), `expected_disposition`
  (`FailClosed`), `observed_disposition`
  (`FailClosed | Breach | NotRun { reason: TargetMissing }`),
  `target_status` (`Bound | Missing`), `outcome` (`Held | Finding |
  TargetMissing`), conditional `finding_severity` (`Low | Medium | High |
  Critical`), `assertion_scope`, and `explicit_limits`. The signed scenario
  manifest fixes `breach_severity` for each class. `Held` requires a
  bound production target and exact expected disposition; `TargetMissing`
  requires `observed_disposition = NotRun { reason: TargetMissing }` and is
  never a pass or a fabricated breach. Cross-field validation is total: `Held`
  requires `observed_disposition = FailClosed` and no severity;
  `Finding` requires `observed_disposition = Breach` and the scenario's exact
  fixed severity; `TargetMissing`
  requires `High`; and a panic overrides the scenario mapping and requires
  `Critical`. Any other combination rejects. This
  mirrors `AutonomousQualificationCase` (`model.rs:532`) without borrowing its
  external-evidence meaning.
- `chio.econsim.qualification-matrix.v1`. Aggregate. Fields: `schema`,
  `profile_id`, `harness_provenance`, and
  `cases: Vec<scenario-result>`. Validated like
  `validate_autonomous_qualification_matrix` (`validation.rs:794`):
  supported schema, non-empty `profile_id`, non-empty `cases`, unique
  scenario ids, non-empty `requirement_ids`, and explicit limits per case.
  The diagnostic runner may assemble a matrix containing any outcome, but the
  signing boundary rejects `TargetMissing` and unresolved High or Critical
  findings. `harness_provenance` binds the git commit, clean/dirty state plus
  source-tree digest, executable SHA-256, `Cargo.lock` digest, enabled feature
  set, target triple, rustc and Cargo versions, exact normalized command,
  scenario-manifest digest, corpus-manifest digest, and runner key id. The
  driver recomputes each local digest before signing and rejects a mismatch.
  These fields remain runner assertions rather than independent execution
  proof. Admissible internal matrices are signed as
  `SignedExportEnvelope<QualificationMatrix>`
  (`lineage.rs:421`). The signature authenticates the runner and binds its
  internal run assertion only.

### CI integration

Add an econsim facet manifest under `ci-gates/`, structured like
`ci-gates/runtime.toml` (`runtime.toml:1`): a fail-closed table that
enumerates exactly the v1 scenario classes, rejects an unknown class, and
carries a manifest-enumeration test that rejects a short manifest. Each
entry names the committed `chio.econsim.qualification-matrix.v1` fixture to
schema-validate and the existing crate or conformance test selectors that
re-run the campaign and assert observed equals expected. The gate is advisory
(non-blocking) first, as the `runtime-attack-simulation` facet models attack
fixtures without gating unrelated work (`runtime.toml:98`, laundering docs
at `runtime.toml:107`), then promotes to blocking per class once stable. A
newly observed `Finding` opens a finding record routed to the owning
workstream; it never silently flips a matrix to green. The runner exits nonzero
when any High or Critical finding remains unresolved or any scenario reports
`TargetMissing`, writes diagnostic scenario results, and emits no signed
qualification matrix, even while the repository-wide facet remains advisory.

### Error handling

Fail-closed throughout. A corpus whose bytes do not match the recorded
`corpus_manifest_digest` aborts the run; an unknown scenario class is an
error, matching the arena's unknown-class rejection
(`crates/core/chio-arena/src/adversary/mod.rs:76`); a replay whose two runs
diverge fails the determinism gate; a missing or zero seed rejects; integer
overflow fails closed. A validator panic on
adversarial input is itself a `Finding` (the campaign records `Breach` with
the panic captured), and the runner exits nonzero for its default Critical
severity. A signing failure emits no matrix. Matrix generation never succeeds
past unresolved High or Critical findings, missing severity, invalid
outcome/severity combinations, provenance-digest mismatch, dirty state not
explicitly allowed by the profile, or missing targets.

## Alternatives considered

1. Add the six cases to existing owning-crate tests and `chio-conformance`,
   reusing arena seed and clock helpers where multi-step replay needs them.
   Recommended first step: it exposes missing production targets before a new
   abstraction can make simulated behavior look real. A pure `chio-econ-sim`
   crate may be extracted later only if repeated campaign orchestration cannot
   live cleanly in those existing homes.
2. Extend the arena `Adversary` trait and `chio-adversarial-suite` with
   economic classes. Rejected as the home. The arena models one tool-call
   step and one guard verdict (`mod.rs:114`), refereed by the kernel-guard
   pool. Economic attacks are multi-step campaigns against pure validators
   that return typed errors, not allow/deny verdicts on a single call.
   WS9 reuses the arena's seed, clock, and bundle writer, not its
   per-step adversary model.
3. Extend `chio-autonomy`'s simulation module
   (`CapitalPoolSimulationReport`, `model.rs:389`). Rejected: it couples a
   general wind tunnel to the insurance and capital-pool domain and
   overloads a market crate with adversary logic. WS9 borrows the
   qualification-matrix shape, not the crate. `chio-conformance` and the owning
   crate tests stay the initial home for boolean fail-closed assertions; the
   thin driver owns internal matrix assembly.

## Claim and release framing

WS9 is internal qualification, not external evidence, an underwriting fact, or
a capability claim. A passing
`chio.econsim.qualification-matrix.v1` states only that, on the named
corpora and seed, the tested validators fail closed as declared; it asserts
nothing about untested corpora, live money, or distributed truth
(`2026-07-10-agent-economy-program-design.md:121`). A `Finding` is a bug in
the owning workstream, never a claim that Chio "supports" the attacked
behavior. Self-signing authenticates the signer and binds the asserted byte
digests, but it does not prove execution and supplies no independent
observation. Matrix digests must not be consumed as underwriting or insurance
evidence; any future external claim requires an independently run qualification
campaign and a separately reviewed evidence policy.

## Testing strategy

- Per-class fail-closed unit tests against the real validator: single-feed
  sybil flood stays tier_2; a divergent feed trips `CircuitBreakerTripped`;
  stale rates fail `ensure_fresh`; a retry sequence converges to `DeadLetter`;
  a mismatched-authority ask fails to mint. Credit exhaustion and cumulative
  fee structuring assert `NotRun { reason: TargetMissing }` plus a
  `TargetMissing` High outcome until their named admission validators exist.
- Determinism gate: two runs of one seed produce byte-identical
  scenario-results and matrix, mirroring
  `crates/core/chio-arena/tests/determinism_gate.rs` and `rng_determinism.rs`.
- Corpus-digest test: mutating one corpus byte changes the manifest digest
  and the engine refuses to run.
- Schema conformance: `chio.econsim.*` fixtures validate against the
  committed schemas (invariant 5,
  `2026-07-10-agent-economy-program-design.md:110`); the matrix validator
  enforces unique ids and non-empty cases.
- `fee-structuring` cannot report `Held` from the per-request constraint. Its
  deterministic `TargetMissing` High finding keeps the runner nonzero until a
  cumulative admission validator is supplied.
- Exit-status tests prove a High or Critical finding, a panic, or a missing
  target prevents successful matrix generation; Low and Medium findings remain
  visible and policy-controlled. Cross-field tests prove a `Finding` without the
  scenario's fixed severity, `TargetMissing` below High, or `Held` with severity
  rejects; a panic is always Critical regardless of that mapping.
- Provenance tests mutate the source tree, executable, lockfile, feature set,
  command, and corpus after manifest assembly and assert signing rejects; the
  signed result is still labeled a runner assertion, not execution proof.
- Signed-schema tests cover registry, hash manifest,
  `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, positive fixtures, and unknown-schema
  negatives when signed matrix artifacts are retained.
- The workspace gate passes before any phase is declared done.

## Implementation phases

1. Honest targets first (may land in wave 2). Extend existing owning-crate and
   `chio-conformance` tests for the four bound assertions; record
   `credit-exhaustion` and `fee-structuring` as `TargetMissing`; reuse arena
   determinism helpers and add the thin internal-matrix driver plus
   signed-schema gates. No new crate in this phase.
2. Control-gap dependency. `AE-CREDIT-ADMISSION-1` and
   `AE-CUMULATIVE-APPROVAL-1` land through WS1 Phase 3 and protocol-primitives
   Tasks 3-6 respectively, with the exact operation-owned APIs, atomic account
   state, and races above. WS9 reruns both scenarios against those named
   production functions. Until then the runner remains nonzero, Wave 3 cannot
   enter, and no matrix is signed.
3. Suite breadth (wave 3). Expand all six classes with seeded multi-step
   populations, reference corpora, and `chio-conformance` assertions. Any breach
   is filed as a finding and High or Critical findings keep the runner red.
   Extract a pure crate only if duplication demonstrates a real boundary.
4. Promotion and internal qualification. Promote stable bound classes from
   advisory to blocking and publish the first internal qualification matrix.
   Do not register it as an underwriting or insurance evidence input.

## Resolved implementation choices

1. Each scenario targets the earliest named production boundary that establishes
   its assertion. The bid flow receives test-key-signed inputs because that
   target verifies signatures; a post-verification pure validator receives
   already-normalized synthetic state only when the scenario manifest names and
   limits that boundary. The manifest records which verification occurred.
2. `spec/PROTOCOL.md` gains the `chio.econsim` artifact-family registry and
   internal-qualification semantics, while explicitly stating that these
   artifacts are not runtime wire messages or underwriting evidence. Every
   schema still enters the registry, hash manifest, fixtures, and unknown-version
   negatives required by program invariant 5.
