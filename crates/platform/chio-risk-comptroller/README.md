# chio-risk-comptroller

Verifier for risk comptroller reports: signed JSON documents in which an
external risk/insurance authority asserts that a transaction's risk facility,
coverage, reconciliation, premium, actuarial evidence, capital, reserve
ledger, and claim appeals are internally consistent. The crate checks a
report's signature, its internal cross-references, and (for a set of reports
sharing a facility) portfolio-wide capital adequacy; it does not price risk,
admit capital, or execute payouts.

It sits in `crates/platform` and is consumed by `chio-control-plane`,
`chio-commerce-order`, `chio-enterprise-export`, `chio-trust-market-context`,
and `chio-proof-room` wherever a risk comptroller report needs to be admitted
as evidence for a `TransactionPassport`.

## Responsibilities

- Parse a `chio.risk.comptroller-report.v1` report into `RiskComptrollerReport`,
  rejecting unknown fields on every nested struct.
- Validate a report's internal consistency: facility state and lifecycle
  replay, coverage binding, reconciliation balance, premium binding, actuarial
  backtest limits, capital decomposition and instructions, reserve ledger and
  sanction reserve ledger arithmetic, and claim appeals.
- Verify a report's Ed25519 signature against a caller-supplied set of trusted
  authority public keys.
- Check a portfolio of reports sharing a facility for capital adequacy and for
  reserve double-consumption across reports.
- Confirm evidence refs cited inside a report (authority receipts, settlement,
  jurisdiction, supporting evidence) are present in a caller-supplied evidence
  graph, via a callback so the crate stays independent of any concrete
  evidence-graph representation.

## Public API

- `RiskComptrollerReport` - parsed report. `id`, `order_id`, `subject`, and
  `signature` are public fields; `verified_claims()` returns the claim ids the
  comptroller asserts. Every other field is private, so the report schema is
  an implementation detail behind the validators.
- `RiskEvidenceRefKind` - `AuthorityReceipt`, `SupportingEvidence`,
  `ReserveLedgerReceipt`, `Settlement`, `Jurisdiction`.
- `validate_risk_report(passport, report)` - full internal-consistency check
  against a `TransactionPassport`.
- `validate_signed_risk_report(passport, report_value, trusted_authority_keys)`
  - signature check, deserialize, then `validate_risk_report`.
- `validate_risk_report_signature(report_value, trusted_authority_keys)` -
  signature check only, against a raw `serde_json::Value`; usable by callers
  that deserialize the report into their own type.
- `validate_risk_portfolio_reports(reports)` - cross-report capital adequacy
  and reserve consumption.
- `validate_risk_evidence_refs(report, contains_ref)` - evidence-graph
  membership check via callback.

## Usage

```rust
use chio_risk_comptroller::validate_signed_risk_report;

let report = validate_signed_risk_report(&passport, &report_value, &trusted_authority_keys)?;
for claim in report.verified_claims() {
    // admit claim into the transaction passport's claim set
}
```

## Testing

`cargo test -p chio-risk-comptroller`

`tests/risk_comptroller.rs` reads fixtures from
`fixtures/proof-room/enterprise-export/` and cross-checks report acceptance
against `spec/schemas/chio-risk/v1/comptroller-report.schema.json` with the
`jsonschema` crate. `[lib] test = false`, so there are no unit tests in `src/`.

## See also

- `chio-transaction-passport` - supplies `TransactionPassport` and
  `TransactionPassportError`; every failure this crate returns is
  `RiskComptrollerClaimFailed`.
- `chio-control-plane`, `chio-commerce-order`, `chio-enterprise-export`,
  `chio-trust-market-context`, `chio-proof-room` - consumers that admit risk
  comptroller reports as evidence.
