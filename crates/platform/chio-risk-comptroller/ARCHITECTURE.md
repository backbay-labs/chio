# chio-risk-comptroller architecture

## Overview

`chio-risk-comptroller` is a pure verifier: no I/O, no runtime state. Its only
external inputs are the trusted-key list passed to the signature checks and
the `contains_ref` callback passed to `validate_risk_evidence_refs`. It treats
every report as untrusted input from an external risk/insurance authority:
every struct in the schema derives `#[serde(deny_unknown_fields)]`, and a
report is only ever converted into `verified_claims()` after its signature,
its internal cross-references, and its ledger arithmetic all check out. The
crate constructs `chio_transaction_passport::TransactionPassportError` values
but does not call into that crate's own claim-set verification; it is called
by `chio-control-plane`, `chio-commerce-order`, `chio-enterprise-export`,
`chio-trust-market-context`, and `chio-proof-room` wherever those crates need
to admit a risk comptroller report as evidence.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | `RiskComptrollerReport` and its sub-artifact types (facility, coverage, reconciliation, premium, actuarial, capital, appeal), the five public entry points, and validators for facility lifecycle, coverage binding, reconciliation, premium, actuarial limits, capital decomposition and instructions, claim appeals, and cross-report portfolio adequacy. |
| `src/ledger.rs` | Private submodule (`mod ledger`). Reserve ledger and sanction reserve ledger validation: lane semantics, per-entry checks, reserve consumption and slash / reverse-slash arithmetic, sanction-bridge to market-slash binding. |

## Report verification lifecycle

1. `validate_risk_report_signature` reads `report_value["signature"]`,
   requires the `sig-ed25519:<public-key-hex>:<signature-hex>` form, resolves
   the public key against the caller's `trusted_authority_keys`, strips the
   `signature` field, and verifies the remainder via
   `PublicKey::verify_canonical` (RFC 8785 canonical JSON).
2. `validate_signed_risk_report` runs that check, then deserializes the JSON
   `Value` into `RiskComptrollerReport`; an unrecognized field fails closed at
   this step via `deny_unknown_fields` before any validator runs.
3. `validate_risk_report` runs the cross-reference checks in a fixed order:
   schema id and passport id match, verdict/state gates, the
   `claim.risk.comptroller_report_bound` marker claim, facility state and
   lifecycle replay, coverage binding, reconciliation, premium, actuarial
   limits, capital decomposition, claim appeals, reserve ledger, sanction
   reserve ledger, capital instructions, claim/coverage scope, facility
   closure.
4. Callers holding multiple reports against the same facility call
   `validate_risk_portfolio_reports` to check aggregate capital adequacy and
   that no reserve is consumed twice across reports.
5. Callers that need to bind a report's referenced ids to an evidence graph
   call `validate_risk_evidence_refs` with a `contains_ref` closure; the crate
   never reads the evidence graph itself.

## Invariants and failure modes

- Every failure is `TransactionPassportError::RiskComptrollerClaimFailed`; the
  crate never constructs another error variant.
- Facility lifecycle replay is a state machine started at `evidence_cold`,
  using `is_allowed_risk_facility_transition` as the only edge set. A report's
  declared `facility.state` must be reached by consuming each lifecycle
  transition exactly once; validation replays from `evidence_cold` rather than
  trusting input order, so transitions may arrive in any order.
- Capital and reserve arithmetic uses `checked_add` / `checked_sub`
  throughout (reserve consumption, portfolio obligations, capital
  decomposition deductions); overflow is a validation error, not a panic.
- A reserve ledger entry is scoped to `coverage.covered_claim_ids` and to
  `facility.reserve_ref`. A `market_slash` entry additionally requires a
  `sanction_bridge` bound to `coverage.subject` and capped by
  `maximum_slash_units`.
- Terminal reserve consumption (`claim_payout`, `reserve_release`,
  `reserve_slash`, `market_slash`, `write_off`) is single-use per
  `(reserve_ref, claim_id)` pair within a report; `reverse_slash` can only
  unwind units already consumed by a prior `reserve_slash` on the same pair.
- Every `claim_payout` reserve entry must bind exactly one
  `RiskCapitalInstruction` matching its order, claim, reserve, currency,
  units, and settlement ref, and that instruction must be pre-observed
  (`intended_state: pending_execution`, `reconciled_state: not_observed`, no
  `observed_execution_ref`) so a report can never assert a payout that has
  already executed.
- An open claim appeal blocks only its own `claim_id`, and only the reserve
  lanes or `facility_closure` it names in `blocks`; appeals scoped to claims
  outside `coverage.covered_claim_ids` are rejected.
- `validate_risk_portfolio_reports` treats a shared `(subject,
  capital_currency)` pair as one capital pool and a shared `reserve_ref` as
  one reserve pool. It rejects capital adequacy breaches, reserve
  overconsumption, a `(reserve_ref, claim_id)` pair consumed by a terminal
  lane in more than one report, reused reserve ledger receipt refs, and a
  reserve ref reused across different `facility_id`s.

## Dependencies

Internal: `chio-core-types` supplies `PublicKey` and `Signature` for the
authority signature check. `chio-transaction-passport` supplies
`TransactionPassport` (for the `passport_id` cross-check) and this crate's
only error type, `TransactionPassportError`. External: `chrono` parses and
orders the RFC 3339 actuarial backtest window timestamps; `serde` /
`serde_json` deserialize the report and its signed JSON payload. No
dependency aliasing.
