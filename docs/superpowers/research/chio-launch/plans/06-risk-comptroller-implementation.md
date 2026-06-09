# Risk Comptroller Implementation Plan

Status: implementation plan
Depends on: `../architecture/06-risk-comptroller-system.md`
Confidence: moderate.

## Objective

Make risk, facility, and insurance context auditable enough to remain in the launch story.

## Registry Acceptance

Risk reports that affect public launch claims are verifier-facing artifacts. The risk comptroller report, facility state report, coverage decision, claim case file, appeal, sanction/reserve ledger, portfolio reconciliation report, capital adequacy report, and actuarial backtest report must use `../indices/artifact-registry.md` names and satisfy `../architecture/09-integration-contracts.md` before launch copy can cite them.

## Phase 0 - Scope And Claim Freeze

Tasks:

1. Freeze the public claim as auditable risk-finance context for autonomous commerce.
2. Block claims that Chio runs autonomous insurance, proves premium adequacy, clears external capital, supports a multi-provider capital stack, reconciles portfolio reserves, or operates a permissionless insurer network.
3. Add protocol text for risk comptroller report and facility state report.
4. Add copy gate that blocks unsupported autonomous insurer pricing claims.

Tests:

- documentation lint or review checklist catches unsupported claims;
- risk schemas reject missing subject, facility, reserve, or reconciliation fields.

## Phase 1 - Risk Comptroller Report

Tasks:

1. Add `chio.risk.comptroller-report.v1` schema.
2. Implement report assembler over underwriting, appraisal, provider passport, reputation, federation, facility, bond, reserve, coverage, claim, payout, settlement, governance, and slashing refs.
3. Implement reconciliation checks.
4. Emit deterministic verifier report section.

Tests:

- valid report passes;
- missing reserve state fails;
- stale reputation snapshot fails under policy;
- coverage not bound to order id fails.

## Phase 2 - Facility State Machine

Tasks:

1. Add `chio.risk.facility-state-report.v1` schema.
2. Implement compact public states: `evidence_cold`, `underwriting_ready`, `facility_granted`, `reserve_held`, `capital_allocatable`, `coverage_bound`, `claim_open`, `claim_decided`, `payout_matched`, `settlement_matched`, `reserve_controlled`, and `closed`.
3. Implement transition verifier.
4. Bind transitions to authority receipts and policy ids.
5. Add replay from facility events to facility state.

Tests:

- invalid transition fails;
- facility active without capital fails;
- claim opened outside coverage period fails;
- close with unreconciled reserve fails.

## Phase 3 - Ledger Separation

Tasks:

1. Define separate ledgers for claim payout, reserve release, reserve slash, and market slash.
2. Add common account reference model.
3. Add double-consumption detector.
4. Add settlement binding for payouts and slashes.
5. Add `chio.risk.sanction-reserve-ledger.v1`.
6. Add `chio.risk.claim-appeal.v1` and gate payout, reserve release, reserve slash, write-off, and closure on appeal state.

Tests:

- same reserve cannot be paid and released;
- same reserve cannot be slashed twice;
- market slash cannot consume facility reserve;
- payout settlement wrong claim id fails.

## Phase 4 - Passport And Commerce Integration

Tasks:

1. Bind risk comptroller report into Transaction Passport.
2. Bind coverage decision into commerce order context.
3. Add provider passport, reputation, and federation evidence as local-policy inputs.
4. Add Proof Room risk tab.

Tests:

- commerce order requiring coverage cannot complete without risk report;
- Transaction Passport fails unreconciled risk report;
- Proof Room shows facility state and ledger reconciliation.

## Phase 5 - Actuarial Evidence Track

Tasks:

1. Define `chio.risk.actuarial-backtest-report.v1`.
2. Define `chio.risk.capital-adequacy-report.v1`.
3. Define capital charge logic.
4. Define governance approval path for automated pricing.
5. Define portfolio reconciliation report for reported, accepted, denied, disputed, awarded, paid, settled, reimbursed, recovered, written off, released, slashed, mismatched, and appeal-blocked amounts by currency.

Tests:

- pricing claim blocked without backtest artifact;
- reserve adequacy below threshold blocks automated coverage;
- capital charge mismatch fails.

## Phase 6 - Launch Fixture

Tasks:

1. Build a valid risk comptroller fixture for a commerce transaction.
2. Add invalid fixtures for double consumption, stale reputation, missing coverage binding, and wrong payout settlement.
3. Add docs that accurately describe risk and insurance support.

Exit criteria:

- risk and insurance context can appear in the homepage story as verifiable evidence;
- autonomous pricing is not overclaimed;
- every reserve-affecting transition is replayable and fail-closed.

## Required Launch Gates

1. `risk_comptroller_valid_fixture_passes`: a complete commerce risk fixture verifies from one report.
2. `risk_missing_reserve_fails`: coverage or payout cannot proceed without required reserve state.
3. `risk_mixed_currency_fails`: cross-currency netting rejects.
4. `risk_subject_mismatch_fails`: mismatch across passport, underwriting, facility, coverage, claim, payout, or settlement rejects.
5. `risk_double_consumption_fails`: same reserve cannot be paid, released, or slashed twice.
6. `risk_market_slash_facility_reserve_fails`: market slash cannot consume facility reserve without an explicit sanction/reserve bridge.
7. `risk_claim_appeal_holds_release_and_slash`: open appeal blocks closure, release, punitive slash, and write-off unless policy explicitly permits emergency payout.
8. `risk_settlement_mismatch_blocks_closure`: amount or counterparty mismatch creates non-terminal state.
9. `risk_actuarial_claim_without_backtest_fails`: autonomous pricing or reserve adequacy copy cannot pass without backtest and capital adequacy artifacts.
