# Risk Comptroller, Facility, And Insurance

Status: architecture outline
Primary source: `../agent-drafts/06-risk-comptroller-facility-insurance.md`
Confidence: high for missing control-plane diagnosis, moderate for actuarial and capital modeling details.

## Position

Risk and insurance should stay in the launch story, but only if represented as verifier-grade state. The right launch claim is auditable risk-finance context, not live autonomous insurance, external capital clearing, or reserve adequacy.

The missing artifact is not a new insurance product. It is the risk comptroller report that reconciles existing underwriting, appraisal, reputation, facility, reserve, bond, claim, payout, settlement, governance, slashing, and passport evidence.

## Core Artifact

`chio.risk.comptroller-report.v1` is a signed projection over existing risk and finance artifacts.

Fields:

- `report_id`
- `subject`
- `transaction_passport_ref`
- `commerce_order_ref`
- `underwriting_ref`
- `appraisal_ref`
- `provider_passport_ref`
- `reputation_snapshot_ref`
- `federation_trust_bundle_ref`
- `facility_state_ref`
- `bond_state_ref`
- `reserve_state_ref`
- `capital_book_ref`
- `coverage_decision_ref`
- `claim_case_ref`
- `payout_ledger_ref`
- `settlement_ref`
- `governance_action_refs`
- `slashing_refs`
- `risk_verdict`
- `exposure_summary`
- `reconciliation_summary`
- `signature`

This report is a projection, not a new source of authority. It fails if its referenced ledgers do not reconcile.

## Hard Launch Claims

Chio can credibly claim:

- signed risk evidence for underwriting review;
- deterministic underwriting decisions with immutable decision history;
- economic-position ledgers per currency;
- bounded facility artifacts with utilization, reserve, concentration, TTL, and capital-source terms;
- reserve posture and reserve-control events;
- custody-neutral capital instructions;
- curated liability-provider policy and bound coverage under explicit provider support;
- bounded claim, dispute, adjudication, payout, and settlement artifact chains;
- local-governance market penalty slashing;
- web3 settlement execution receipts with finality and recovery posture.

Chio must not claim without additional artifacts:

- autonomous insurance operation;
- premium adequacy;
- external capital clearing;
- multi-provider capital stack support;
- insurance portfolio reserve reconciliation;
- first-class claim appeals;
- unified slashing;
- permissionless insurer network or risk market.

## Facility State Machine

`chio.risk.facility-state-report.v1` should make facility lifecycle the launch contract.

The public launch state model should be compact:

1. `evidence_cold`
2. `underwriting_ready`
3. `facility_granted`
4. `reserve_held`
5. `capital_allocatable`
6. `coverage_bound`
7. `claim_open`
8. `claim_decided`
9. `payout_matched`
10. `settlement_matched`
11. `reserve_controlled`
12. `closed`

Every transition binds:

- prior state;
- next state;
- authority receipt;
- policy id;
- evidence refs;
- affected reserve/bond/capital accounts;
- invariant result;
- signature.

The report can still expose detailed transition reasons. Launch reviewers need the verdict and blocking invariant more than a large internal state diagram.

## Ledger Separation

The risk system must separate four accounting flows:

1. Claim payout: consumes claim reserve to pay beneficiary or counterparty.
2. Reserve release: frees unused reserved capital.
3. Reserve slash: penalizes facility reserve for covered failure.
4. Market slash: penalizes market participant bond or stake.

Double consumption is a launch blocker.

Additional risk artifacts:

- `chio.risk.claim-appeal.v1` for appeal blocks that supersede future projection only and never rewrite original signed claim artifacts;
- `chio.risk.sanction-reserve-ledger.v1` for reserve slash, market slash, hold, reverse slash, punitive amount, claim-priority amount, appeal-blocked amount, and consumed reserve ids;
- `chio.risk.portfolio-reconciliation-report.v1` for all open and recently closed facility claims by currency;
- `chio.risk.actuarial-backtest-report.v1` before any premium adequacy or autonomous pricing claim.

## Ledger Invariants

1. Currency invariant: never net exposure, premium, reserve, capital, payout, settlement, recovery, or slash across currencies.
2. Subject invariant: passport subject, underwriting subject, exposure subject, facility subject, bond subject, coverage subject, claim subject, payout subject, settlement subject, and reputation subject must match or cite a signed migration or portfolio binding.
3. Reserve invariant: held reserve plus locked reserve minus released reserve, slashed reserve, impaired reserve, and claim consumption must stay above required reserve for allocatable states.
4. Capital invariant: available capital equals committed capital minus held, drawn, disbursed, and impaired capital, clamped at zero and partitioned by source and currency.
5. Premium invariant: bound premium must match quote and coverage; collected premium must cite observed payment or settlement proof.
6. Claim invariant: payable amount must be zero unless the claim is accepted under policy or adjudicated with an upheld or partial-settlement outcome.
7. Payout invariant: payout instruction amount must equal payable amount, and paid state requires matched payout receipt.
8. Settlement invariant: settlement amount cannot exceed payout amount, and matched settlement requires observed amount, payer, and payee to match instruction topology.
9. Slash invariant: one reserve-control source, market penalty, or governance case cannot consume the same reserve twice. Reverse slash must reference the exact prior enforced hold or slash.
10. Closure invariant: facility closure fails with any open appeal, unresolved claim, payout mismatch, settlement mismatch, unreconciled recovery, unresolved write-off approval, appeal-blocked reserve, or unresolved reverse-slash state.

## Gate Model

Gate 1: underwriting admission.

- Verify subject, exposure class, limits, exclusions, underwriting evidence, appraisal evidence, and policy version.

Gate 2: facility activation.

- Verify capital, reserve, bond, governance approval, and risk appetite.

Gate 3: coverage binding.

- Verify commerce order, provider passport, reputation snapshot, federation trust, transaction passport, premium or fee context, and effective time.

Gate 4: claim opening.

- Verify event, coverage period, evidence, claimant, and transaction binding.

Gate 5: claim decision.

- Verify policy coverage, exclusions, loss evidence, fault posture, dispute posture, and appeal rules.

Gate 6: payout or slash.

- Verify ledger availability, no double consumption, authority receipt, settlement proof, and governance constraints.

Gate 7: closure.

- Verify all reserves, claims, payouts, slashes, appeals, and settlement refs reconcile.

## Insurance Claim Discipline

Launch can claim:

- Chio can bind insurance and risk context into autonomous commerce proof.
- Chio can make underwriting, coverage, reserve, claim, payout, and slash evidence auditable.
- Chio can fail closed when risk state is unreconciled.

Launch should not claim:

- autonomous insurer pricing is production-ready;
- actuarial pricing is proven;
- reserve adequacy is proven across markets;
- reinsurance or capital stack behavior is live unless separately verified.

Those require backtests, capital charge logic, reserve adequacy analysis, and governance policy review.

## Passport Integration

Risk nodes attach to Transaction Passport as:

- `risk.underwriting_evidence`
- `risk.facility_state`
- `risk.coverage_decision`
- `risk.claim_case`
- `risk.reserve_state`
- `risk.payout_ledger`
- `risk.slashing_event`
- `risk.comptroller_report`

The passport verifier should fail required risk claims if the comptroller report is absent or unreconciled.

## Negative Cases

- coverage binds after exposure event;
- facility active without capitalized reserve;
- claim payout and reserve release both consume same reserved amount;
- slash references wrong participant;
- risk report references stale reputation snapshot;
- coverage decision not bound to order id;
- payout settlement proof does not bind claim id;
- market slash consumes facility reserve without explicit sanction/reserve bridge;
- claim appeal remains open while release, slash, write-off, or closure advances;
- cross-currency netting hides short reserve state;
- autonomous pricing claim lacks actuarial evidence.
