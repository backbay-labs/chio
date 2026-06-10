# Commerce Order Implementation Plan

Status: implementation plan
Depends on: `../architecture/02-commerce-order-system.md`
Confidence: moderate.

## Objective

Turn autonomous commerce from example logic into a verifier-grade order context.

## Registry Acceptance

Commerce artifacts that appear in a Transaction Passport or verifier report must pass the registry acceptance contract in `../indices/artifact-registry.md` and `../architecture/09-integration-contracts.md`. Do not call an order context, event log, provider admission report, settlement packet, or order passport supported until registry, manifest, constants, claim/proof rows, positive fixture, and unknown-schema negative fixture exist.

## Phase 0 - Contract Freeze

Tasks:

1. Add protocol text for `chio.commerce.order-context.v1`.
2. Add schemas for order context, event log, order event, provider admission, quote binding, mandate binding, budget reservation, payment evidence, fulfillment evidence, settlement packet, dispute evidence, reconciliation evidence, and order passport.
3. Define state machine transitions and invariants.
4. Define AP2, x402, and ACP-Commerce projection blocks as subordinate evidence.
5. Add copy guidance that never uses bare `ACP`.

Tests:

- schema accepts valid order context;
- schema rejects missing order id, event log digest, current state, or authority receipt;
- replay rejects unknown transition.

## Phase 1 - Replay Ledger

Tasks:

1. Implement event log parsing.
2. Implement deterministic replay to materialized state.
3. Implement transition invariant checks.
4. Implement replay verifier report.

Tests:

- valid fixture replays to `completed`;
- quote amount drift fails;
- mandate expiry fails;
- duplicate event id fails;
- settlement observed before settlement dispatched fails.

## Phase 2 - Runtime Commerce Admission

Tasks:

1. Add a commerce admission path that checks intent, provider, quote, mandate, budget, payment, and fulfillment before settlement dispatch.
2. Bind provider passport, reputation snapshot, and federation trust bundle into provider admission.
3. Require budget reservation before payment capture or settlement dispatch.
4. Keep settlement observer as post-dispatch reconciliation evidence.

Tests:

- invalid provider passport denies admission;
- stale reputation snapshot denies or downgrades according to policy;
- payment proof for wrong merchant denies;
- observer event cannot advance state without dispatch packet.

## Phase 3 - External Protocol Bridges

Tasks:

1. Add AP2 mandate projection.
2. Add x402 challenge/verify/settle projection.
3. Add ACP-Commerce delegated-payment projection.
4. Add web3 settlement proof bundle reference.
5. Add bridge-specific negative fixtures.

Tests:

- AP2 mandate hash mismatch fails;
- x402 payment requirement mismatch fails;
- ACP-Commerce token wrong seller fails;
- web3 settlement proof wrong order id fails.

## Phase 4 - Passport Integration

Tasks:

1. Add `chio.commerce.order-passport.v1`.
2. Add Transaction Passport node and edge classes for commerce.
3. Add Proof Room commerce tab.
4. Add CLI report section for order replay.

Tests:

- Transaction Passport fails if order context digest differs from order passport digest;
- Proof Room displays current state and failed gate;
- redacted commerce fields honor disclosure policy.

## Phase 5 - Launch Qualification

Tasks:

1. Promote one existing web3 or agent-commerce example into a canonical commerce fixture.
2. Add a valid complete fixture and at least six invalid fixtures.
3. Add docs showing which external protocols are evidence sources.
4. Add release gate that runs commerce replay verifier.

Exit criteria:

- "autonomous commerce" claim maps to order-context verifier output;
- settlement proof is not accepted without order binding;
- all commerce launch docs use `ACP-Commerce` where relevant.
