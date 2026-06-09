# Agent L Risk Facility Capital Deepening Review

Status: refinement review
Scope: risk, facility, insurance, capital, reserve, claims, slashing, and settlement reconciliation
Confidence: high for current repo and protocol boundaries; moderate for proposed implementation order; low for any external carrier, reinsurer, custodian, or regulated-capital assumption until partner artifacts exist.

## Bottom Line

The hard truth is that Chio can credibly launch a signed risk-finance evidence stack, but not a live insurance, capital-market, or reserve-adequacy system. The repo already has deterministic underwriting, exposure ledgers, facility and bond artifacts, capital books, capital instructions, provider policies, quote and bind artifacts, claim packages, disputes, adjudications, payout receipts, settlement receipts, governance leases, market penalty artifacts, web3 execution receipts, oracle checks, and anchor proofs. That is enough to claim "auditable risk and insurance context" if it is framed tightly.

It is not enough to claim that Chio operates autonomous insurance, verifies reserve adequacy, clears external capital, runs a permissionless risk market, or reconciles a portfolio-grade facility. The launch blocker is the absence of one signed, replayable risk comptroller projection that joins all those local artifacts and refuses to advance state when underwriting, facility, reserve, claim, payout, settlement, reputation, governance, or slashing facts disagree.

## Evidence Base

- Protocol risk exports: behavioral-feed, underwriting-input, underwriting-decision, signed decisions, appeals, and exposure ledger are explicitly scoped and bounded in `spec/PROTOCOL.md:1784-1902`.
- Facility and capital surfaces: facility policy, provider risk package, capital book, capital instructions, and allocations are bounded in `spec/PROTOCOL.md:2074-2235`.
- Bond, loss, reserve, claim, payout, settlement, and launch boundary language is explicit in `spec/PROTOCOL.md:2307-2446`.
- Premium pricing is deterministic score-band pricing with fail-closed missing compliance score handling, not actuarial pricing, in `crates/chio-underwriting/src/premium.rs:1-29` and `crates/chio-underwriting/src/premium.rs:293-365`.
- Facility and bond artifacts expose limits, reserve ratio, concentration cap, TTL, lifecycle, and support boundaries in `crates/chio-credit/src/lib.rs:520-636` and `crates/chio-credit/src/lib.rs:720-836`.
- Capital book and capital execution separate source-of-funds truth from external execution truth in `crates/chio-credit/src/credit/capital_and_execution.rs:54-166` and `crates/chio-credit/src/credit/capital_and_execution.rs:270-520`.
- Liability provider, pricing authority, placement, bound coverage, claim, payout, and settlement validators are in `crates/chio-market/src/provider.rs:12-111`, `crates/chio-market/src/quote.rs:337-584`, `crates/chio-market/src/placement.rs:13-288`, `crates/chio-market/src/claim.rs:52-375`, and `crates/chio-market/src/settlement.rs:87-590`.
- Market slashing is a separate governance and open-market lane in `crates/chio-open-market/src/penalty.rs:17-180` and `crates/chio-open-market/src/evaluation.rs:340-496`.
- Web3 settlement projects approved capital instructions into bounded execution receipts and finality assessment, not ambient capital truth, in `crates/chio-settle/src/lib.rs:1-99`, `crates/chio-settle/src/observe.rs:103-240`, and `crates/chio-settle/src/evm/finalize.rs:51-122`.

## Hard Launch Claims

1. Chio can produce signed risk evidence for underwriting review. The claim is strong because behavioral-feed and underwriting-input reuse canonical receipt, settlement, reputation, certification, runtime-assurance, metering, and shared-evidence state instead of creating an untracked telemetry path.

2. Chio can produce deterministic underwriting decisions and preserve decision history immutably. The claim is strong if copy says decisions have bounded outcomes, lifecycle state, review state, budget recommendation, premium state, and appeal linkage, not that Chio has an insurer-grade pricing model.

3. Chio can expose an economic-position ledger per currency. The exposure ledger can show governed ceiling, reserve, settlement, provisional loss, recovered amount, and premium projections. The claim must include the support boundary: no cross-currency netting, no full claim-adjudication closure, and no finalized recovery lifecycle from this ledger alone.

4. Chio can issue a bounded facility artifact. The facility can grant, manually review, or deny a single-currency credit limit with utilization, reserve, concentration, TTL, and capital-source terms. The claim must say bounded policy surface, not live capital market.

5. Chio can express reserve posture and reserve-control events. Bond policy can lock, hold, release, or impair reserve; loss lifecycle can record delinquency, recovery, reserve release, reserve slash, and write-off as immutable artifacts with appeal-window and reconciliation state.

6. Chio can produce custody-neutral capital instructions. The instructions prove intent, authority chain, source kind, rail, execution window, intended state, and observed reconciliation status. They do not prove external movement unless matched execution evidence exists.

7. Chio can curate liability-provider policy and bind coverage under explicit provider support. Provider policy can name admitted carrier, surplus line, captive, or risk pool; coverage classes; jurisdiction; currency; evidence requirements; claims support; quote TTL; and bound coverage support.

8. Chio can run a bounded claim package, provider response, dispute, adjudication, payout, and settlement artifact chain. The validators enforce coverage window, amount ceiling, subject alignment, denied-or-partial dispute precondition, payable adjudication, matched payout receipt, settlement topology, authority chain, and amount or counterparty mismatch states.

9. Chio can represent market penalty slashing as a local-governance market discipline artifact. It can hold, slash, or reverse slash when governance, fee schedule, bond requirement, listing, activation, and prior-penalty checks pass. It is not permissionless global slashing.

10. Chio can project web3 settlement execution into receipts with finality and recovery posture. The claim is strongest when the proof binds approved capital instruction, dispatch, chain id, escrow or bond state, tx hash, finality, anchor proof, oracle evidence, and recovery action.

## Blocked Claims

1. Blocked: "Chio runs autonomous insurance." Current support is deterministic evidence, bounded pricing authority, quote/bind, and claim orchestration. Autonomous insurer pricing remains blocked without actuarial backtests, reserve adequacy, capital charge, drift stops, and governance-approved authority envelopes.

2. Blocked: "Chio proves premium adequacy." The premium model is a compliance-score band plus optional behavioral penalty. It does not model frequency, severity, loss adjustment expense, IBNR, tail capital, reinsurance, credibility, attachment, exhaustion, or portfolio concentration.

3. Blocked: "Chio clears external capital." Capital instructions are custody-neutral intent. External execution must be proven by observed execution, payout receipt, settlement receipt, or web3 execution receipt.

4. Blocked: "Chio supports a multi-provider capital stack." The current capital book is intentionally conservative and fails closed on mixed currency, missing subject, contradictory counterparty, multiple live facilities or bonds, and no active granted facility. That is good safety, but not senior capital plus first-loss reserve plus insurer plus reinsurer plus custodian.

5. Blocked: "Chio reconciles insurance portfolio reserves." There is no portfolio ledger for earned premium, unearned premium, IBNR, LAE, ceded premium, reinsurance recoveries, salvage, subrogation, write-offs, and settlement lag across all claims.

6. Blocked: "Chio has a first-class claim appeal system." Underwriting appeals exist, reserve-control appeal state exists, and claim disputes/adjudications exist. A claim appeal that can supersede an adjudication or block payout, release, slash, closure, or write-off is not present as a canonical artifact.

7. Blocked: "Chio has unified slashing." Reserve slash and open-market slash are separate accounting lanes. Without a sanction ledger, Chio cannot prove no double slash, claim-first priority, reverse-slash restoration, or reserve-control appeal ordering across both.

8. Blocked: "Chio is an insurer network or permissionless risk market." The protocol says the liability-market claim is bounded to curated provider admission, pricing authority, quote/bind, and claim/dispute/adjudication/payout-and-settlement orchestration, not insurer network, open-ended recovery clearing, or permissionless market.

9. Blocked: "Settlement context is complete for launch commerce." Settlement proof is strong after dispatch, but commerce and risk need pre-dispatch order binding plus portfolio-level payout, recovery, reimbursement, reserve, and write-off reconciliation.

10. Blocked: "A reviewer can verify the full risk claim today from one root." The risk comptroller report, facility state report, facility passport, and Proof Room risk tab are planned, not the current single public proof root.

## Artifact Gaps

1. Risk comptroller report. Add one signed `chio.risk.comptroller-report.v1` or normalize the existing spelling to one canonical name. It must reference the transaction passport, commerce order, underwriting, appraisal, reputation, facility, bond, reserve, capital book, coverage, claim, payout, settlement, governance, slashing, and verifier policy artifacts. It must fail closed on missing required refs, signature failure, stale evidence, subject mismatch, currency mismatch, duplicate consumption, and unreconciled final state.

2. Facility state report. Add one replayed `chio.risk.facility-state-report.v1` over immutable events. The state machine should not be editable state. It should be derived from ordered artifacts and include current state, blocked transitions, balances, policy ids, authority refs, and invariant results.

3. Facility passport. Add a compact launch artifact that says whether a subject is facility-ready: active passport, valid reputation inputs, approved underwriting, granted facility, active bond, required reserve held, capital source available, coverage status, open claim count, payable amount, paid amount, unrecovered amount, slashed amount, settlement mismatch count, and closure blocks.

4. Capital adequacy report. Add `chio.risk.capital-adequacy-report.v1` with reserve requirement, held reserve, available capital, utilization, concentration, stress scenario, capital charge, model version, data window, and governance approval. The first version can be conservative and deterministic, but it must be explicit.

5. Actuarial backtest artifact. Add `chio.risk.actuarial-backtest-report.v1` with input event table hash, policy snapshot, model version, predicted frequency, predicted severity, observed claims, observed payouts, reserve adequacy, cohort drift, and reproducible result hash.

6. Claim case file. Add `chio.risk.claim-case-file.v1` as the canonical case projection over claim package, response, dispute, adjudication, appeal, payout, settlement, recovery, reimbursement, reserve release, reserve slash, write-off, and closure state.

7. Claim appeal artifact. Add a signed appeal artifact for adjudication, payout mismatch, settlement mismatch, reserve slash, or closure dispute. It must supersede future projection only and never rewrite the original signed claim artifacts.

8. Sanction and reserve ledger. Add one ledger that names reserve slash, market slash, hold, reverse slash, punitive amount, claim-priority amount, appeal-blocked amount, and consumed reserve ids. This is the double-consumption guard.

9. Portfolio reconciliation report. Add one report over all open and recently closed facility claims: reported, accepted, denied, disputed, awarded, paid, settled, reimbursed, recovered, written off, released, slashed, mismatched, and appeal-blocked amounts by currency.

10. Proof Room risk fixture set. Add one valid facility claim path plus negative fixtures for missing reserve, stale reputation, mixed currency, claim outside coverage, duplicate receipt id, payout amount mismatch, settlement counterparty mismatch, double reserve consumption, market slash against facility reserve, reverse slash without prior enforced penalty, and closure with open appeal.

## Facility State Model

The state model should be narrower than the draft's full long-list state machine for launch. The launch version needs fewer public states and stricter substate details:

1. `evidence_cold`: required evidence missing or stale.
2. `underwriting_ready`: signed underwriting input and decision are current.
3. `facility_granted`: active granted facility exists for one subject and one currency.
4. `reserve_held`: required bond or reserve exists and is not impaired, expired, or appeal-blocked.
5. `capital_allocatable`: capital book resolves exactly one live source and allocation is not simulation-only execution.
6. `coverage_bound`: quote, placement, and bound coverage are current and provider supports claims.
7. `claim_open`: claim package is valid and inside coverage.
8. `claim_decided`: accepted, denied, or adjudicated outcome has strict payable semantics.
9. `payout_matched`: payout instruction and observed payout receipt reconcile.
10. `settlement_matched`: recovery, reimbursement, or facility reimbursement settlement reconciles amount and counterparties.
11. `reserve_controlled`: release, slash, hold, or reverse slash is reconciled and appeal state is closed or explicitly blocking.
12. `closed`: no open claim, dispute, appeal, payout mismatch, settlement mismatch, recovery, write-off approval, reserve control, or reverse slash remains.

The public state should be compact. The report can still expose detailed transition reasons. Launch reviewers need a verdict and the blocking invariant, not a 40-state internal diagram.

## Ledger Invariants

1. Currency invariant: never net exposure, premium, reserve, capital, payout, settlement, recovery, or slash across currencies.

2. Subject invariant: passport subject, underwriting subject, exposure subject, facility subject, bond subject, coverage subject, claim subject, payout subject, settlement subject, and reputation subject must match or cite a signed migration or portfolio binding.

3. Reserve invariant: `held_reserve + locked_reserve - released_reserve - slashed_reserve - impaired_reserve - consumed_by_claim >= required_reserve` for allocatable states.

4. Capital invariant: `available_capital = committed_capital - held_capital - drawn_capital - disbursed_capital - impaired_capital`, clamped at zero and partitioned by source and currency.

5. Premium invariant: bound premium must match quote and coverage; collected premium must cite observed payment or settlement proof; earned premium must cite coverage period and earning rule.

6. Claim invariant: payable amount must be zero unless the claim is accepted under policy or adjudicated with claim-upheld or partial-settlement outcome.

7. Payout invariant: payout instruction amount must equal payable amount, and paid state requires matched payout receipt.

8. Settlement invariant: settlement amount cannot exceed payout amount, and matched settlement requires observed amount, payer, and payee to match instruction topology.

9. Slash invariant: one reserve-control source, market penalty, or governance case cannot consume the same reserve twice. Reverse slash must reference the exact prior enforced hold or slash.

10. Closure invariant: facility closure fails with any open appeal, unresolved claim, payout mismatch, settlement mismatch, unreconciled recovery, unresolved write-off approval, appeal-blocked reserve, or unresolved reverse-slash state.

## Implementation Priorities

### P0: Claim Ceiling And Root Projection

1. Freeze public copy around the bounded claim: Chio provides auditable risk-finance artifacts and deterministic orchestration, not insurer status, reserve adequacy, external capital clearing, or permissionless market operation.
2. Normalize artifact names for risk comptroller and facility state across index, architecture, roadmap, schemas, and verifier output.
3. Add schemas for risk comptroller report, facility state report, claim case file, and sanction/reserve ledger.
4. Implement a read-only comptroller assembler over existing signed artifacts. It should verify signatures, recompute hashes, enforce subject and currency coherence, and emit one verdict plus failures.
5. Add double-consumption detection for payout versus release versus reserve slash versus market slash.
6. Add negative fixtures before adding happy-path fixture polish.

### P1: Facility, Claim, And Settlement Reconciliation

1. Implement facility replay from ordered artifacts with deterministic ordering by event time, artifact type priority, and artifact id.
2. Add claim appeal as a first-class signed artifact and wire it into payout, reserve release, reserve slash, write-off, and closure gates.
3. Add portfolio reconciliation by facility and currency over open claims, payouts, settlements, recoveries, reimbursements, releases, slashes, and write-offs.
4. Bind risk comptroller report into Transaction Passport and Proof Room risk tab.
5. Gate coverage binding and claim payout on active passport lifecycle, local reputation policy, issuer allowlist, and blocking negative-event evaluation.

### P2: Capital Adequacy And Actuarial Track

1. Build the actuarial event table from signed artifacts.
2. Implement deterministic expected-loss and capital-charge reports with conservative priors.
3. Add reserve adequacy and stress scenario reports by facility, provider, coverage class, jurisdiction, tool class, runtime assurance tier, and reputation band.
4. Add reinsurance and external capital refs only as explicit external artifacts, not implicit Chio authority.
5. Only then consider expanding autonomous pricing authority beyond bounded operator-visible simulation.

## Required Launch Gates

1. `risk_comptroller_valid_fixture_passes`: a complete valid commerce risk fixture verifies from one report.
2. `risk_missing_reserve_fails`: coverage or payout cannot proceed without required reserve state.
3. `risk_mixed_currency_fails`: any cross-currency netting attempt rejects.
4. `risk_subject_mismatch_fails`: mismatch across passport, underwriting, facility, coverage, claim, payout, or settlement rejects.
5. `risk_double_consumption_fails`: same reserve cannot be paid, released, or slashed twice.
6. `risk_market_slash_facility_reserve_fails`: market slash cannot consume facility reserve without an explicit sanction/reserve bridge.
7. `risk_claim_appeal_holds_release_and_slash`: open appeal blocks closure, release, punitive slash, and write-off unless policy explicitly permits emergency payout.
8. `risk_payout_preobserved_instruction_fails`: payout instruction rejects a capital instruction that already claims observed execution.
9. `risk_settlement_mismatch_blocks_closure`: amount or counterparty mismatch creates non-terminal state.
10. `risk_actuarial_claim_without_backtest_fails`: autonomous pricing or reserve adequacy copy cannot pass the launch copy gate without backtest and capital adequacy artifacts.

## Final Assessment

The launch story should keep risk and insurance, but only as proof-backed context. The correct claim is:

"Chio binds underwriting, facility, reserve, coverage, claim, payout, settlement, governance, slashing, and reputation evidence into a fail-closed risk comptroller report for autonomous commerce."

That claim becomes defensible after the risk comptroller report, facility state report, sanction/reserve ledger, claim case file, and risk Proof Room fixtures exist. Without those artifacts, the stronger insurance and capital claims should be blocked.
