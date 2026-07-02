# Chio Points Program Spec (Usage-Recognition Metric)

Date: 2026-07-02. Status: brainstorm, design-support. Not legal advice.
Scope: the Hyperliquid copy-list rank-1 mechanism (usage-based points, copy now, pre-token)
adapted to Chio's fail-closed house rules. This is a PRE-TOKEN, ZERO-TOKEN-PROMISE design:
an internal, recompute-only usage-recognition metric over already-signed usage truth.
Sources: `CHIO-TOKEN-INVARIANTS.md` (invariants 6, 11, 13), `CHIO-TOKEN-EXTERNAL-LANDSCAPE-2026-07.md`
(Section 4 copy-list rank 1, Section 3 EigenLayer anti-pattern), `CHIO-TOKEN-COUNSEL-PACKET.md`
(cover-note item 3, TOK-GATE-AD). Binds to real metering/receipt/registry surfaces cited inline.
Framing: fail-closed. A violation is a design rejection, not a trade-off.

## 1. Purpose and the NO-TOKEN-PROMISE disclaimer

Purpose: recognize genuine economic usage of Chio so the protocol can (a) rank and reward
real activity internally, (b) bank an insider-excluded, attested usage history that a
retroactive gift COULD later draw on IF and only if counsel ever opens that gate, and
(c) do so without ever creating a claim, expectation, or wink of future value.

NO-TOKEN-PROMISE DISCLAIMER (binds every artifact, string, and telemetry surface):
- Points are a usage-recognition metric ONLY. They are NOT a token, NOT a claim on any
  token, NOT convertible to any asset, and carry NO promise, hint, or expectation of any
  future distribution. There is no announced conversion rate, snapshot date, or eligibility
  formula, and none will be pre-announced (invariant 13; invariant 6 "no published farmable
  formula pre-snapshot").
- Why this is a hard rule, not caution: EigenLayer's prospective points program became
  "the largest information asymmetry that exists in crypto" (Robert Leshner) and a broken
  social contract at drop (CoinDesk, 2024-05-09). Points-before-token accrues expectation
  debt whenever conversion is implied but unspecified. Chio refuses to incur that debt.
- Consequence: this mechanism is built and computed INTERNALLY (devnet/internal only,
  nothing public, no announcement, no "points" label externally) until counsel clears any
  public program. Any externally visible metric inherits the EigenLayer risk profile and is
  therefore in scope of the no-future-value recital (invariant 13; counsel packet item 3).
- Token conversion of any kind is EXPLICITLY DEFERRED TO COUNSEL under TOK-GATE-AD
  (retroactive airdrop to US persons, incl. announcement timing), which is BLOCKED-EXTERNAL
  and defaults to NO. This spec makes no conversion claim and reaches no legal conclusion.

## 2. Scoring over NET economic usage (never raw volume)

The score recognizes NET economic contribution, not gross activity, so wash traffic and
self-dealing cannot inflate it. Hyperliquid's points program rewards sustained real volume
and penalizes wash trading (Hyperliquid docs; PANews); Chio copies the intent with fees and
completions as the substrate. All inputs already exist as signed usage truth.

Inputs (each a projection over already-signed receipts/metering, Section 3):
- Net x402 settlement fees actually paid. From `X402PaymentRequirements`
  (`crates/economy/chio-settle/src/payments.rs`: `amount_minor_units`, `currency`,
  `settlement_mode`), counted only on settled payments. NET means fees paid minus fees
  received on the counterparty leg, so a closed A->B->A loop nets to zero.
- Completed escrows. A `ChioEscrow` counts only on `EscrowReleased(escrowId, amount,
  receiptHash)` (`contracts/src/ChioEscrow.sol`); `EscrowRefunded` and never-released
  escrows contribute nothing. Rewarding completion, not creation, denies open-and-cancel farms.
- Metered compute actually consumed. From `CostMetadata` (`crates/economy/chio-metering/src/cost.rs`:
  `receipt_id`, `agent_id`, `tool_server`, `tool_name`, `dimensions`, `total_monetary_cost`)
  exported via `create_billing_export` (`export.rs`, schema `chio.billing-export.v1`).
  `BudgetEnforcer` (`budget.rs`) already caps spend per session/agent/tool, bounding any
  single actor's inflation surface.
- Quality attestation signals (weighting multiplier, not a volume term). From
  `chio-reputation` tiers (`crates/trust/chio-reputation/src/tier.rs`: `tier_0`..`tier_3`)
  computed by `issuance.rs` over `ChioReceipt` attribution. NOTE: EAS-anchored attestations
  are research-only on this branch (implementation on `chio/m2-build`, unmerged); until
  merge, the native quality substrate is `chio-reputation` deltas plus `chio-credentials`
  attested DIDs, not EAS.

Formula shape (illustrative; constants are policy, published as recognition, Section 4):
`score = w_fee * net_fees_paid + w_escrow * completed_escrow_value + w_compute * metered_spend`,
the whole scaled by a reputation-quality multiplier `q(tier) in [0,1]` and a per-actor
diminishing-returns cap. All terms are USD-minor-unit magnitudes over signed receipts; no
term rewards gross count or transaction frequency.

Anti-sybil / anti-wash rules (analogous to Hyperliquid's wash-trading penalties):
- Net-of-counterparty accounting (above) is the primary wash defense: circular value that
  returns to origin contributes zero, so co-conspirator loops cannot farm the score.
- Observation-cost commitments make attested-usage signals costly to forge.
  `chio-pheromone` requires a verified `chio.pheromone-observation-cost-commitment.v1`
  (validation.rs `verify_observation_cost_commitment`, unit `chio.observation.microunit.v1`,
  RFC6962-sha256 telemetry) with FAIL-CLOSED `ObservationCostVerificationMode::Required`;
  a deposit without a proven cost commitment is rejected. Points weight only signals that
  cleared this gate.
- sqrt(N) passport cap and diversity cap. `chio-pheromone` already bounds influence per
  passport at `sqrt(active_peers)` (`SqrtNPassportCapExceeded`) and per pair
  (`DiversityCapExceeded`); the score adopts the same caps so N cheap identities net far
  less than one genuine actor.
- Tier-3 Sybil gate reuse. Reputation `tier_3` requires composed score AND per-feed floor
  0.80 AND >= 2 distinct feeds (`tier.rs`); the quality multiplier inherits this, so a flood
  from one feed cannot lift `q(tier)`.
- Pass refresh-on-genuine-use as sybil resistance. The Chio Pass refreshes allotment ONLY
  on genuine metered use and gates NEW allotment only, never claws back (invariant 4); an
  idle or synthetic Pass earns no recognition because it produces no signed usage to score.

## 3. Recompute-only architecture (no new ledger)

The program is a deterministic PROJECTION over already-signed truth, never a new source of
record (invariant 11: recompute-only, no chain RPC in the TCB, fail-closed on inconsistency).

- Inputs are signed receipts and metering exports that already exist: `ChioReceipt`,
  `CostMetadata`/`BillingExport`, x402 settlement artifacts, `EscrowReleased` events.
- Verification is against PUBLISHED roots, not live balances. Receipt/metering history is
  anchored in `ChioRootRegistry` (`contracts/src/ChioRootRegistry.sol`); each scored leaf is
  checked with `verifyInclusionDetailed(proof, root, leafHash, operator)`, which returns
  false unless `publishedRoots[operator][root]` holds and `ChioMerkle.verifyRFC6962` passes.
  The bare `verifyInclusion` reverts `ProofMetadataRequired` by design (fail-closed).
- No chain RPC enters the trusted path. Any actor-scoped input reaches the kernel only as a
  signed attestation through `chio-credentials`, never a live balance call (invariant 11).
- Recomputable and idempotent. Given the same signed history and the same published formula,
  every recompute yields the identical score; any inconsistency (missing proof, unpublished
  root, tampered leaf) fails closed to zero recognition for that leaf, never a guess.
- No new mutable ledger, balance store, or "points database of record." The metric is a
  view derived on demand; deleting it and recomputing from receipts must reproduce it exactly.

## 4. Season structure and transparency

- Seasons. Recognition accrues in bounded epochs (seasons) over Merkle-proven usage, a
  continuous per-epoch stream with NO calendar cliff and nothing that unlocks on a date
  (invariant 6). A season is an accounting window over signed history, not a countdown to a drop.
- Publish the recognition formula. The scoring function, weights, caps, and net-of-counterparty
  rules are published so any actor can recompute their OWN score from their OWN signed receipts
  and verify it. This transparency is about recognizing usage already done; it is a mirror of
  truth the actor already holds, not a promise.
- No farmable pre-announcement of any conversion. Publishing the recognition formula is NOT
  publishing a token-eligibility or conversion formula. There is NO pre-announced snapshot
  date, eligibility rule, or point->asset mapping (invariant 6 "no published farmable formula
  pre-snapshot"; invariant 13). IF counsel ever opens TOK-GATE-AD, any retroactive gift uses
  an unpredictable snapshot announced only AFTER the fact (Uniswap/Jito pattern), so a known
  recognition score cannot be farmed toward a known target.
- Insider exclusion, recorded now. Team, contributor, and investor addresses are excluded
  from any future gift the recognition history could feed (Jito/RetroPGF precedent; invariant 12).
- Comms discipline. No "points," "airdrop," "snapshot," or future-value language in any public
  channel, telemetry, or UI until counsel clears it (invariant 13; counsel packet item 3).

## 5. Build vs already-exists

Already exists (read-only substrate; no new trust surface needed to compute a score):
- Metering: `BudgetPolicy`/`BudgetEnforcer` (`budget.rs`), `CostMetadata` (`cost.rs`),
  `create_billing_export` / `BillingExport` (`export.rs`).
- Settlement: `X402PaymentRequirements` and settlement artifacts (`payments.rs`); `ChioEscrow`
  with `EscrowReleased`/`EscrowRefunded` (`contracts/src/ChioEscrow.sol`).
- Anchoring: `ChioRootRegistry.publishRoot` + `verifyInclusionDetailed` (RFC6962 Merkle,
  fail-closed) as the published-root check.
- Reputation: `ReputationTier` tiers and `issuance.rs` over `ChioReceipt` for the quality multiplier.
- Sybil substrate: `chio-pheromone` observation-cost commitments, sqrt(N) passport cap,
  diversity cap; Chio Pass refresh-on-genuine-use.

Needs to be BUILT (all recompute-only, no new ledger):
- The scoring projector: a deterministic function that reads signed receipts/exports, verifies
  each leaf against a published `ChioRootRegistry` root, applies the net-of-counterparty and
  cap rules, and emits a per-actor score. Fail-closed on any unverifiable leaf.
- Net-of-counterparty settlement accounting: pairing paid vs received legs across x402/escrow
  so closed loops net to zero (not currently computed as a netted quantity).
- The quality-multiplier binding from `chio-reputation` tiers into the score, and the EAS
  quality substrate once `chio/m2-build` merges (research-only here).
- Season windowing and per-actor accumulation as a derived view, plus an insider-exclusion list.
- A self-verify tool: given an actor's signed receipts and the published formula, recompute
  and display their score locally.

Explicitly NOT built here and DEFERRED TO COUNSEL: any token, any conversion, any snapshot,
any public "points" program, and any external announcement. Those close only on TOK-GATE-AD
(BLOCKED-EXTERNAL, defaults to NO).
