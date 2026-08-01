# FV-D3: Conservation laws for the M2 economy surface

Status: Blocked (2026-07-15; scalar groundwork implemented, collection surface unmerged)
Theme: D - Widen the verified frontier
Effort: M
Depends on: [FV-A1](FV-A1-absorb-verified-helpers.md) (absorbed-helper pattern, receipt-coupling phase), chio-anchor multi-crate Kani precedent
Feeds: [FV-C5](FV-C5-proof-coverage-map.md) (new covered surface), [FV-C1](FV-C1-receipt-trace-validation.md) (settlement receipt coupling)
Related docs: [../GAP_ANALYSIS.md](../GAP_ANALYSIS.md) (G2 pattern applied to a new crate family), `crates/economy/chio-anchor/src/kani_public_harnesses.rs`, `.kani/harnesses.toml`

## Summary

The `chio/m2-build` branch contains a netting collapse and a settlement recompute lane in the economy crates, both written in a deliberately fail-closed checked-arithmetic style, and neither collection surface is touched by any proof lane. This document specifies conservation laws for that surface - per-currency conservation of channel sums, recompute/collapse idempotence, per-currency isolation, and overflow-denies fail-closure - and plans a `formal_economy.rs` pure-core module verified with Kani and Creusot for the collection-level laws, Aeneas extraction for the two scalar conversion helpers only, and a bounded Lean model whose conservation theorem is the candidate for a new property id P11 in the proof manifest. Provenance note: the netting and recompute code cited below was read this session from branch `chio/m2-build` (verified via `git show`; the M2 merge is pending), so all economy-crate line numbers are branch-qualified; this plan lands after that merge and its first phase re-verifies the citations against main.

## Blocked execution record

The audited groundwork that does not depend on the missing M2 netting surface is complete:

- `chio-credit::formal_economy` now exposes checked `u128` ceil and floor conversion helpers that return `Option<u64>`, with unit tests, a full-width randomized property test, the exhaustive four-bit PR Kani harness `public_convert_rounding_envelope`, and the full-width boundary harness `public_convert_overflow_fails_closed`.
- `chio-web3::settlement::settlement_state_id` is now a public pure helper used directly by `verify_public_settlement_proof`. Its nine-state truth table is covered by a unit test and the PR Kani harness `public_settlement_state_id_fixed_point`, which uses exact byte-slice patterns without comparison loops, and an identical-input runtime test pins verifier determinism.
- The multi-crate Kani registry, PR path classifier, formal mapping, generated coverage, and current-state counts include all three new harnesses.
- The Aeneas production registry is now manifest-driven across the kernel core and `chio-credit::formal_economy`. Authenticated Charon and Aeneas regenerate byte-identical `FormalAeneas` and `FormalEconomy` snapshots, and generated ceil/floor functions are proved equivalent to the root-imported natural-number conversion model. The model proves both rounding envelopes without placeholders.
- The pinned Aeneas support closure now includes its upstream `Aeneas.Std.Scalar.Casts` module because the economy source is the first registered extraction target that widens `u64` to `u128` and narrows the checked result. The vendor script and content digest reproduce that closure.
- Focused cargo-mutants discovery finds 25 mutants across both new conversion functions. A local targeted campaign caught all 25 with zero missed, timeout, or unviable outcomes, but no scheduled registry result is claimed. Proof-mutant onboarding remains part of production absorption because the current lane is intentionally limited to the kernel model sources.

The remainder is blocked because `crates/economy/chio-credit/src/netting.rs` and the M2 collection APIs are not present on the committed branch. `git ls-tree` confirms that both the target branch and the execution branch lack the module, while `chio/m2-build` contains it and is not an ancestor of the execution branch. No parallel collapse API has been invented. Collection-level conservation, isolation, idempotence, aggregate overflow, production absorption, the three named Creusot contracts, four collection Kani harnesses, L1/L3/L4, receipt coupling, and P11 remain unclaimed. The scalar Aeneas/Lean evidence and settlement determinism evidence are complete independent groundwork.

## Motivation and evidence

- The code already states its own laws in prose; nothing checks them. `chio/m2-build:crates/economy/chio-credit/src/netting.rs` (1389 lines, read this session) is explicit: conversions "round UP so the netted view never understates exposure" (L155-156), recovery channels round DOWN so a net loss is never shrunk (L216-222), every aggregate add is checked and fails closed on overflow "because a capped figure understates the netted exposure" (L418-431), pinned USD/USDC parity cannot be overridden (L285-307), duplicate currency rows are rejected because they "manufacture a phantom capital_freed" (L510-523), and truncated source reports are refused (L565-583). These are conservation and no-understatement laws written as comments and unit tests; they are exactly the shape Kani and Creusot pin mechanically.
- Money is the one place a wrapped add is indistinguishable from theft. The netting benefit `capital_freed_units = segregated - netted` (L536) is a published financial figure; any silent wrap, mis-rounding, or double-count in the channels feeding it misstates exposure to whoever consumes the netted view.
- The precedent for verifying a non-kernel crate exists and works. `crates/economy/chio-anchor/src/kani_public_harnesses.rs` (read this session, current HEAD): five harnesses behind Cargo feature `kani = ["web3"]` (`chio-anchor/Cargo.toml` L50), registered in `.kani/harnesses.toml` (rows verified at L266-281) with pr/nightly lanes, bounded enum pickers (`pick < 5`, L96-104), and an explicit honesty boundary listing which runtime tests cover the one model-only harness (L55-80). FV-D3 copies this pattern wholesale.
- The kernel already has a monetary micro-precedent. `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` L58 defines `monetary_cap_is_subset_by_parts` (currency equality projected by the caller), and `MonetaryAmount` exists in core types with `ToolGrant`/`Attenuation` carrying monetary caps. The economy laws extend the same discipline one crate family outward.

## Current state

Netting (owning crate `chio-credit`, branch `chio/m2-build`):

- `CanonicalConversionRate::convert` (netting.rs L193): u128 widening multiply, `div_ceil` round-up, `u64::try_from` narrowing that errors as `ConversionOverflow`; zero numerator and zero denominator each fail closed (L194-203).
- `CanonicalConversionRate::convert_floor` (L231): round-down twin used only for the recovery channel (L395-416, `convert_position`).
- `ExposureLedgerNettingRates::rate_for` (L285): explicit rate wins for non-pinned currencies; USD/USDC accept only parity overrides (`PinnedParityOverride`); missing rate is `MissingRate`, never an implicit parity guess.
- `collapse_positions_to_canonical` (L501): rejects duplicate currencies, converts each position, sums channel-wise via `checked_aggregate_add` (L421), computes the segregated baseline from per-position `outstanding_exposure_units`, and returns the netted view with `capital_freed_units` as a saturating subtraction (L536; the ONLY saturating aggregate, justified because a benefit floors at zero rather than understating exposure).
- `ExposureLedgerCurrencyPosition::outstanding_exposure_units` (`chio/m2-build:crates/economy/chio-credit/src/lib.rs` L301-317): `checked_add(pending, failed)` erroring as `UnsettledExposureOverflow`, `saturating_sub(provisional_loss, recovered)` (a loss cannot go negative), then `max` of the three capital channels.
- `ExposureLedgerReport::collapse_to_canonical` (netting.rs L565): refuses truncated reports. A `do_not_weaken` regression suite (L588+) freezes the support-boundary flags.

Recompute (owning crate `chio-web3`, branch `chio/m2-build`):

- `verify_public_settlement_proof` (`settlement_proof.rs` L489): "Settlement state is recomputed from the kernel-signed checkpoint anchor and the chain snapshot, not trusted from any producer-asserted or witnessed on-chain value" (doc, L468-481); emits `recomputed_settlement_state` (L570); withholds the finality claim without an independent chain head (L524-540). The function is pure in `(bundle, trust)`.

Proof lanes: the two prerequisite scalar/state helpers now have public Kani rows and runtime tests. The scalar conversion helpers also have manifest-driven Aeneas extraction, generated equivalence, and root-imported Lean envelope theorems. The absent M2 collection surface still has no Kani collection, Creusot, or L1/L3/L4 Lean evidence.

## Design

### The laws, stated as checkable properties

L1 - Per-currency conservation (channel-sum conservation across the collapse). For any position set accepted by `collapse_positions_to_canonical` under all-parity rates, each netted channel equals the checked sum of the input positions' corresponding channels; equivalently, the collapse neither mints nor drops units - it only re-denominates. Under non-parity rates the exact-sum form is replaced by the two-sided rounding bound (L2). ("Sum of net positions equals zero" is the classic bilateral form of this law; the Chio collapse is a projection over one ledger rather than pairwise obligations, so conservation is stated as sum-preservation of every channel, with `capital_freed = segregated - netted` as the derived quantity that must never be manufactured - the duplicate-currency rejection at L510-523 is precisely the guard against phantom `capital_freed`, and law L3 covers it.)

L2 - No-understatement rounding envelope (scalar). For `convert`: `Ok(v)` implies `v * denominator >= units * numerator` and `(v - 1) * denominator < units * numerator` (least upper rounding). For `convert_floor`: `Ok(v)` implies `v * denominator <= units * numerator < (v + 1) * denominator`. Together with the channel orientation table (exposure channels use `convert`, recovery uses `convert_floor`, verified at L399-415), this yields the module's headline claim: the netted view never understates exposure.

L3 - Per-currency isolation. A currency's units enter the canonical book only through its own declared rate: missing rate errors (never implicit parity), pinned currencies accept only parity overrides, and duplicate rows for one currency are rejected rather than aggregated. No cross-currency term appears in any channel other than through `rate_for(currency)`.

L4 - Collapse idempotence (the netting form of recompute idempotence). Collapsing the singleton `[view.netted_position]` under default (parity) rates is a fixed point: the netted position is unchanged and `capital_freed_units = 0`. A second-order corollary: `collapse(collapse(P).netted_position) = collapse(P).netted_position`.

L5 - Recompute idempotence (settlement). `verify_public_settlement_proof` is deterministic in `(bundle, trust)`: two invocations yield identical reports, and re-verifying a bundle whose `recomputed_settlement_state` was already recomputed yields the same state id (fixed point of `settlement_state_id`). This is a purity/determinism law, not a numeric one; it is pinned by a differential test plus a Kani harness over the small `lifecycle_state -> state id` mapping rather than the full verifier (the full function transits signature verification, out of Kani scope per the chio-anchor precedent's own boundary note).

L6 - Checked-arithmetic fail-closure. Every aggregate and conversion overflow path returns the named error (`ConversionOverflow`, `UnsettledExposureOverflow`, `AggregateOverflow`); no law-bearing quantity wraps; the only saturating operations are the two justified floors (`capital_freed_units`, net loss), and each is asserted to be a floor-at-zero of a mathematically non-negative quantity, never an exposure channel.

### Where the verified core lives, and the lane split

`crates/economy/chio-credit/src/formal_economy.rs` now mirrors the `formal_aeneas.rs` discipline (pure, no IO, no clocks). Its scalar helpers satisfy the Aeneas source constraints; the future collection wrappers will remain outside the extraction inventory because the lane split is:

- Kani and Creusot take the collection-level laws (L1, L3, L4, L6). Both handle bounded `Vec`/arrays fine, and the real functions (`collapse_positions_to_canonical`, `checked_aggregate_add`, `outstanding_exposure_units`, `rate_for`) can be called directly - the chio-anchor real-API precedent, avoiding the model-only trap its fifth harness documents.
- Aeneas takes ONLY the scalar checked-arithmetic helpers (L2): the production Aeneas lane forbids traits, borrows, `Vec`, and slices in extraction sources, and the netting error type carries `String` currency fields, so `convert`/`convert_floor` cannot be extracted as-is. `formal_economy.rs` therefore hosts `convert_ceil_scalar(units: u64, num: u64, den: u64) -> Option<u64>` and `convert_floor_scalar(...) -> Option<u64>`, the production functions delegate to them (absorption, the [FV-A1](FV-A1-absorb-verified-helpers.md) move, so the proven code IS the running code), and the Lean equivalence theorems state the L2 envelope over the extracted functions.

### Kani harnesses (feature-gated, registered)

In `crates/economy/chio-credit/src/kani_public_harnesses.rs`, module gated `#[cfg(kani)]`, Cargo feature `kani = []` (chio-credit has no `web3`-style crate gate, so no feature implication is needed; the feature exists for tooling parity with chio-anchor):

- `public_collapse_conserves_channels_parity`: 3 symbolic positions (bounded u64 channels), parity rates; assert each netted channel equals the checked sum or the collapse errored (L1, L6).
- `public_convert_rounding_envelope`: symbolic `(units, num, den)`; assert the L2 inequalities on `Ok` results for both scalar helpers. The current PR harness exhausts the four-bit input cube and uses `u16` assertions to keep nonlinear solver cost bounded; the full-width property test and `public_convert_overflow_fails_closed` cover randomized `u64` inputs and the narrowing boundary respectively.
- `public_collapse_idempotent_on_canonical`: collapse a symbolic canonical position; assert fixed point and zero benefit (L4).
- `public_isolation_truth_table`: symbolic rate tables over 2 currencies; assert `MissingRate`/`PinnedParityOverride`/`DuplicateCurrency` fire exactly per L3 (bounded enum-picker style, `pick < N`, per the chio-anchor helpers at L96-114).
- `public_outstanding_exposure_fail_closed`: symbolic near-`u64::MAX` channels; assert overflow yields `Err`, never a wrapped or capped value (L6).
- `public_settlement_state_id_fixed_point`: truth table over the bounded lifecycle enum (L5's Kani-tractable core).

Each harness gets a `[[harness]]` row in `.kani/harnesses.toml` with `crate = "chio-credit"` (and one `chio-web3` row for the state-id harness), `default_unwind = 8` to match the workspace default, `lane = "pr"` where the wall clock allows and `"nightly"` otherwise, with notes following the registry's existing honesty conventions. Bounds: 3-4 parties/positions, symbolic u64 amounts.

### Creusot contracts

`ensures` clauses on `checked_aggregate_add` (result equals sum when `Some`), loop invariant on the collapse accumulation (running netted channels equal running checked sums), and the `outstanding_exposure_units` max-of-channels postcondition. Registered in `formal/rust-verification/creusot-contracts.toml` (the required lane per `proof-manifest.toml` L106).

### Law-to-artifact traceability

One row per law; every law gets at least one PR-time-cheap artifact (a plain `#[test]` differential test) in addition to its proof lane, so a lane outage never leaves a law unwatched:

| Law | Kani harness | Creusot contract | Lean theorem | Aeneas | Plain test |
| --- | --- | --- | --- | --- | --- |
| L1 conservation | `public_collapse_conserves_channels_parity` | collapse loop invariant | `netting_conserves_channel_sums` | - | parity-rate differential test |
| L2 rounding envelope | `public_convert_rounding_envelope` | - | `convert_ceil_envelope`, `convert_floor_envelope` | scalar helpers extracted | property test over small rationals |
| L3 isolation | `public_isolation_truth_table` | - | `collapse_isolated_by_currency` | - | existing unit tests (netting.rs tests) |
| L4 collapse idempotence | `public_collapse_idempotent_on_canonical` | - | `collapse_idempotent` | - | fixed-point `#[test]` |
| L5 recompute idempotence | `public_settlement_state_id_fixed_point` | - | - (out of Lean scope this wave) | - | double-verify differential test |
| L6 overflow fail-closure | `public_outstanding_exposure_fail_closed` | `checked_aggregate_add` ensures | folded into L1/L2 statements | scalar helpers | near-MAX regression tests |

Kani bound parameters (mirroring the chio-anchor conventions): 3-4 symbolic positions, unconstrained symbolic `u64` channel values, `default_unwind = 8`, enum pickers as bounded `u8` with `kani::assume(pick < N)`. The scalar groundwork separately bounds each rounding input to `0..=15`; its registry note names the full-width property and boundary coverage.

### Lean model and the P11 question

`formal/lean4/Chio/Chio/Economy/Netting.lean`: positions as structures of `Nat` channels, rates as `Nat` pairs, `collapse` as a fold; theorems `netting_conserves_channel_sums` (L1), `convert_ceil_envelope`/`convert_floor_envelope` (L2, doubling as the Aeneas equivalence targets), `collapse_idempotent` (L4), `collapse_isolated_by_currency` (L3). Root-imported.

Decision: do not mint P11 while the collection surface is absent. The proved scalar rounding envelope is necessary but does not establish economy channel conservation, isolation, or collapse idempotence. Minting the claim now would overstate the evidence and force unrelated scalar theorems into a collection-level property. Once the netting surface merges and L1/L3/L4 plus their real-API Kani and Creusot bindings pass, P11 should land atomically across the claim registry, proof manifest, theorem inventory, and mapping.

### Settlement receipt coupling

Netting outcomes that are published (the netted view is a signed report surface) follow the `receipt_fields_coupled` pattern: the fields of the published artifact are coupled to the inputs that produced them (`formal_core::receipt_fields_coupled` is a covered symbol, `proof-manifest.toml` L76; Lean `receiptFieldsCoupled`, `Core/Protocol.lean` L121-126). Concretely: a coupling predicate over (source report summary hash, rate table hash, netted view) with a Kani truth-table harness, landing as part of [FV-A1](FV-A1-absorb-verified-helpers.md) phase 5 rather than duplicated here; this plan reserves the predicate name `netting_view_fields_coupled`.

## Implementation plan

1. Post-merge re-verification. Re-cite every branch-qualified location against main after the M2 merge; adjust names if the netting module moved. Files: this document's Current state section (line-number refresh only).
2. Scalar core absorption. The two helpers, manifest-driven second extraction source, committed generated snapshot, and generated Lean equivalence are complete. Production `convert`/`convert_floor` delegation remains blocked until `netting.rs` is present; do not add a parallel production API.
3. Kani harnesses. Add `crates/economy/chio-credit/src/kani_public_harnesses.rs` and the `chio-web3` state-id harness; add the `kani` feature to both Cargo.tomls (with `unexpected_cfgs` check-cfg registration, copying `chio-anchor/Cargo.toml` L85-89); register all rows in `.kani/harnesses.toml`.
4. Creusot contracts. Annotate `checked_aggregate_add`, the collapse loop, and `outstanding_exposure_units`; register in `formal/rust-verification/creusot-contracts.toml`.
5. Lean model. The root-imported scalar conversion model and L2 envelopes are complete. Add `formal/lean4/Chio/Chio/Economy/Netting.lean` and prove L1/L3/L4 only after the collection API is available.
6. P11 mint (single PR). Deferred by decision above until collection evidence exists.
7. Receipt coupling handoff. Land `netting_view_fields_coupled` under FV-A1 phase 5's mechanism; cross-reference from both docs.

## CI and gating changes

- Kani rows enter the existing multi-crate runner via `.kani/harnesses.toml` additively; per the registry's own note (L203-206), no workflow edits are needed for new harnesses. PR-lane wall-clock must be measured; any harness over budget ships as `lane = "nightly"` with a registry note naming the runtime tests that cover the gap PR-time (the chio-anchor L274-281 convention).
- Creusot rides the required `check-rust-verification-gates.sh` lane.
- The Aeneas gates demonstrably exercise the economy symbols through the manifest-driven source inventory. Production extraction checks both generated snapshots and the equivalence gate hashes both source output sets; the negative calibration also kills a semantic mutation in the generated economy conversion.
- Lean rides `check-formal-proofs.sh`; the G1 PR-latency caveat applies until [FV-E3](FV-E3-pr-formal-smoke-tier.md).
- The P11 PR must keep `./scripts/check-proof-report.sh` green (claim gate consistency).

## Acceptance criteria

- [ ] `formal_economy.rs` scalar helpers exist, are called by the production `convert`/`convert_floor` (absorption verified by grep-level call-site check), and are Aeneas-extracted with Lean envelope theorems (L2); removing an economy symbol from the generated Lean makes the extraction gate fail, proving the lane reads the new source rather than only the hard-coded kernel-core path.
- [ ] All six Kani harnesses pass and are registered; at least four call real `pub fn`s directly; any model-only harness carries an explicit honesty-boundary note naming its runtime-test cover.
- [ ] Creusot contracts on the three named functions verify in the required lane.
- [ ] Lean theorems L1, L3, L4 are root-imported and sorry-free.
- [ ] Idempotence and determinism (L4, L5) also pinned by plain `#[test]` differential tests (cheap, PR-time, toolchain-free).
- [x] P11 lands as one PR touching CLAIM_REGISTRY, proof-manifest, theorem-inventory, and MAPPING together, or the decision NOT to mint P11 is recorded here with rationale.
- [ ] No behavior change to the netting module observable by its existing `do_not_weaken` suite.

## Risks and mitigations

- The M2 branch may land with changes to the cited code. Mitigation: phase 1 is a re-verification pass; laws are stated against behaviors (rounding directions, error variants) rather than line numbers.
- Kani blowup on `String`-carrying error enums (the chio-anchor nightly harness note documents exactly this failure mode with `format!` paths). Mitigation: harnesses assert on `Result::is_err`/variant discriminants without constructing display strings; scalar helpers return `Option`/small enums.
- Creusot annotations on a serde-deriving module may fight derive macros. Mitigation: contracts go on the free functions (`checked_aggregate_add`, scalar helpers) and a thin pure wrapper for the loop body if needed.
- Double bookkeeping between Lean model and Rust (G2's trap). Mitigation: the Rust harnesses call production functions; the Lean model's scalar layer is tied down by Aeneas equivalence; only the collection layer is model-plus-harness, and that pairing is stated in the honesty notes.
- Saturating floors could hide a real bug if a "non-negative by construction" claim is wrong. Mitigation: dedicated Kani assertion that the saturating subtractions' operands satisfy `minuend >= subtrahend` under parity rates (where exactness holds), so the floor is provably dead code in the exact case.

## Decisions

- The checked scalar conversion helpers, Aeneas equivalence, Lean envelope
  theorems, and Kani projections are implemented against the surfaces present
  on this branch.
- Collection-level netting, recomputation, isolation, and idempotence remain
  blocked because the required M2 netting surface is absent. The unchecked
  acceptance items stay open.
- No P11 property or public claim is created from scalar groundwork alone.

- The segregated-baseline law remains a corollary of L1 and max monotonicity. The Lean model will prove the corollary and a collection Kani harness will assert it after the M2 surface lands.
- Recompute remains a determinism law here. Lifecycle-ledger replay requires the trace vocabulary and is deferred to a separate implementation after the trace-validation surface is stable.
- Rate-table provenance is an explicit oracle boundary. L3 isolates currencies given an input table; any eventual P11 scope must state that it does not authenticate the table.

## Manifest and registry updates

- `formal/proof-manifest.toml`: the scalar helper module/symbols, settlement-state symbol, conversion root, and Aeneas production entry are registered. The netting module/symbols, P11 property row, and P11 required id remain deferred.
- `formal/assumptions.toml`: no new assumption; the rate table remains an input, documented in the P11 claim scope rather than as an audited assumption.
- `formal/MAPPING.md`: rows for each new Kani harness (exact symbol targeted, assumption discharge `n/a` or ASSUME-SQLITE-ATOMICITY where store-backed inputs are involved).
- `formal/theorem-inventory.json`: P11 mappings remain deferred with the claim. The scalar theorems are root-imported supporting evidence but are not misattributed to P1-P10.
- `docs/reference/CLAIM_REGISTRY.md`: no P11 row until the collection claim is proved.
