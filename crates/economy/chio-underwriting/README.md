# chio-underwriting

`chio-underwriting` defines Chio's underwriting decision, simulation, and
appeal contracts: the risk taxonomy and reason codes, evidence references
(receipt, reputation, certification, runtime assurance, settlement, metered
billing), a fail-closed decision evaluator, a deterministic insurance-premium
pricing formula, and reputation-tiered marketplace credit limits. It builds on
`chio-appraisal` and is consumed by `chio-market`, `chio-credit`,
`chio-kernel`, and `chio-cli`.

The crate is pure data and decision logic: no I/O, no runtime state, and
`#![forbid(unsafe_code)]`. It does not depend on `chio-kernel`; callers supply
kernel-derived inputs (compliance score, behavioral-anomaly score) themselves
so the crate graph (`chio-kernel -> chio-market -> chio-underwriting`) stays
directed.

## Responsibilities

- Defines the risk taxonomy, reason codes, and evidence-reference contracts
  (`UnderwritingRiskClass`, `UnderwritingReasonCode`, `UnderwritingRiskTaxonomy`,
  `UnderwritingEvidenceReference`).
- Evaluates a `UnderwritingPolicyInput` against a `UnderwritingDecisionPolicy`
  and produces a fail-closed decision report and signed artifact
  (`evaluate_underwriting_policy_input`, `build_underwriting_decision_artifact`).
- Prices insurance premiums deterministically from a compliance score and
  optional behavioral-anomaly signal (`price_premium`).
- Computes reputation-tiered marketplace credit limits with fail-closed
  revocation gating (`compute_marketplace_credit_limit`).
- Defines the appeal wire contracts and decision query/list/simulation report
  schemas; it does not implement appeal state transitions or a simulation
  runner (see ARCHITECTURE.md).

## Public API

Re-exported: `appraisal` (= `chio-appraisal`); `canonical`, `capability`,
`crypto`, `receipt` (from `chio-core-types`).

From `decision`:
- `evaluate_underwriting_policy_input`, `build_underwriting_decision_artifact`
  - evaluate a `UnderwritingPolicyInput` and build a `SignedUnderwritingDecision`.
- `UnderwritingDecisionPolicy`, `UnderwritingDecisionReport`,
  `UnderwritingDecisionFinding`, `UnderwritingDecisionArtifact`,
  `UnderwritingBudgetRecommendation`, `UnderwritingPremiumQuote` - policy,
  evaluation output, and derived artifact fields.
- `UnderwritingDecisionQuery`, `UnderwritingDecisionListReport`,
  `UnderwritingSimulationRequest`, `UnderwritingSimulationReport` - query,
  listing, and simulation schemas.

From `premium`:
- `price_premium`, `risk_multiplier` - the pricing formula.
- `PremiumInputs`, `PremiumQuote`, `LookbackWindow`, `PremiumDeclineReason`.

From `marketplace_limits`:
- `compute_marketplace_credit_limit`, `MarketplaceCreditLimitRequest`,
  `MarketplaceCreditLimitDecision`, `MarketplaceLimitTier`.

From the crate root: `UnderwritingPolicyInput`, `UnderwritingPolicyInputQuery`,
evidence types (`UnderwritingReceiptEvidence`, `UnderwritingReputationEvidence`,
`UnderwritingCertificationEvidence`, `UnderwritingRuntimeAssuranceEvidence`,
`UnderwritingComplianceEvidence`), and appeal contracts
(`UnderwritingAppealRecord`, `UnderwritingAppealCreateRequest`,
`UnderwritingAppealResolveRequest`).

## Usage

```rust
use chio_underwriting::{price_premium, LookbackWindow, PremiumInputs, PremiumQuote};

let window = LookbackWindow::new(1_700_000_000, 1_700_003_600).expect("valid lookback window");
let inputs = PremiumInputs::new(Some(820), None, 1_000, "USD");

match price_premium("agent-7", "tool:exec", window, &inputs) {
    PremiumQuote::Quoted { quoted_cents, .. } => println!("premium: {quoted_cents} cents"),
    PremiumQuote::Declined { reason, .. } => println!("declined: {reason:?}"),
}
```

## Testing

`cargo test -p chio-underwriting`

## See also

- `chio-appraisal` - supplies the attestation-verifier-family taxonomy embedded
  in `UnderwritingRuntimeAssuranceEvidence`.
- `chio-market` - calls `price_premium` in its insurance flow and binds quotes
  into policies.
- `chio-credit` - re-exports this crate as `underwriting` and consumes its
  certification and compliance-evidence types for risk reports.
- `chio-kernel` - consumes decision list/outcome types for operator reporting
  and is the intended source of `PremiumInputs.compliance_score`.
- `chio-cli` - calls `compute_marketplace_credit_limit` to gate
  `chio guard market install` by tenant tier and revocation.
- `chio-core` - re-exports this crate as `chio_core::underwriting` in the
  unified protocol facade.
