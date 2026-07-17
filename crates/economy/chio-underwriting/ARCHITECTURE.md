# chio-underwriting architecture

## Overview

`chio-underwriting` is a pure library in the economy layer: in-memory types, a
fail-closed decision evaluator, and two independent deterministic pricing
paths, with no I/O and no runtime state (`#![forbid(unsafe_code)]`). It
depends only on `chio-appraisal` and `chio-core-types`; `chio-market`,
`chio-credit`, `chio-kernel`, `chio-cli`, and the `chio-core` facade depend on
it in turn and convert its outputs into economic authority (credit limits,
bound insurance policies, operator reports). The crate deliberately excludes
`chio-kernel` from its own dependency graph so that `chio-kernel -> chio-market
-> chio-underwriting` stays a directed path; kernel-derived inputs (compliance
score, behavioral-anomaly score) are supplied by the caller.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Evidence, taxonomy, policy-input, and appeal contracts; schema constants and the bounded-limit / filter-validation helpers shared by `decision`. |
| `src/decision.rs` | `UnderwritingDecisionPolicy`, the fail-closed evaluator (`evaluate_underwriting_policy_input`), decision-artifact construction and signing envelope, decision query/list/summary types, and simulation-report types. |
| `src/premium.rs` | Standalone compliance-score premium formula (`price_premium`), risk-multiplier bands, behavioral-anomaly penalty, and decline reasons. |
| `src/marketplace_limits.rs` | Reputation-tiered marketplace credit-limit helper (`compute_marketplace_credit_limit`) with fail-closed revocation gating. |

## Decision lifecycle

1. A caller assembles a `UnderwritingPolicyInput` from signed receipt,
   reputation, certification, runtime-assurance, and compliance evidence
   (typically materialized by the kernel from its receipt store).
2. `evaluate_underwriting_policy_input` validates the policy, then checks
   receipt-history sufficiency and freshness, the compliance-score
   requirement, reputation thresholds, runtime-assurance tier against
   governed-receipt exposure, and per-signal reason codes. Findings are
   deduped and reduced to one `outcome` and one `risk_class`, each taken as
   the maximum over findings under the type's derived `Ord`
   (`Approve < ReduceCeiling < StepUp < Deny`; `Baseline < Guarded < Elevated <
   Critical`).
3. `build_underwriting_decision_artifact` maps the outcome to a
   `UnderwritingReviewState`, derives a `UnderwritingBudgetRecommendation`, and
   prices an embedded `UnderwritingPremiumQuote` from a basis-points table
   keyed by outcome and risk class (`quote_premium_amount`, saturating u128
   intermediate). It computes a content-addressed `decision_id`
   (`uwd-<sha256 of the canonical JSON of schema, issued_at, evaluation,
   supersedes_decision_id, budget, and premium>`).
4. The artifact is wrapped in `SignedUnderwritingDecision`
   (`SignedExportEnvelope<UnderwritingDecisionArtifact>`) for the caller to
   sign and downstream verifiers to check.

`premium::price_premium` is a second, independent pricing path: it prices an
insurance premium directly from a compliance score and optional behavioral
z-score, not from a `UnderwritingDecisionReport`. `chio-market`'s insurance
flow calls it directly instead of going through the decision evaluator.

Simulation (`UnderwritingSimulationRequest`/`Delta`/`Report`) and appeal
(`UnderwritingAppealRecord` and its request types) are schema-only: the crate
defines the wire shapes but ships no simulation runner or appeal
state-transition function. A caller builds a simulation report by invoking
`evaluate_underwriting_policy_input` twice, once per policy, and diffing the
two reports itself.

## Invariants and failure modes

- `evaluate_underwriting_policy_input` returns `Err` on an invalid policy
  (`UnderwritingDecisionPolicy::validate`) before touching any evidence.
- Runtime-assurance evidence is required once `governed_receipts > 0`: missing
  evidence or a tier below `minimum_step_up_runtime_assurance_tier` steps up; a
  tier below `minimum_approve_runtime_assurance_tier` reduces the ceiling; only
  a tier at or above the approve floor clears without a finding.
- Reputation evidence, when present, denies below `deny_reputation_score_below`
  and reduces the ceiling below `minimum_approve_reputation_score`; absent
  reputation evidence produces no reputation finding.
- A signal with reason `RevokedCertification`, `FailedCertification`, or
  `FailedSettlementExposure` always denies, regardless of other findings.
- `UnderwritingPolicyInputQuery::validate` requires at least one anchor
  (`capability_id`, `agent_subject`, or `tool_server`), rejects blank or padded
  filter strings, requires `tool_server` when `tool_name` is set, and rejects
  `since > until`.
- `price_premium` fails closed to `PremiumQuote::Declined` on invalid
  `PremiumInputs`, a missing compliance score, or a combined score below
  `PREMIUM_DECLINE_FLOOR` (500); identical inputs always yield an identical
  quote.
- `compute_marketplace_credit_limit` denies with
  `reason = "publisher_credentials_revoked"` whenever `publisher_revoked` is
  true, regardless of reputation tier.
- Monetary and premium-cents arithmetic saturate instead of overflowing:
  `quote_premium_amount` and `compute_quoted_cents` clamp to `u64::MAX`.

## Dependencies

Internal: `chio-appraisal` supplies `AttestationVerifierFamily` (itself
re-exported from `chio-core-types::runtime_attestation`), embedded in
`UnderwritingRuntimeAssuranceEvidence`; this crate re-exports it as
`appraisal`. `chio-core-types` supplies canonical JSON (`canonical`),
capability types (`RuntimeAssuranceTier`, `MonetaryAmount`), signing and
hashing (`crypto`), and the receipt-lineage `SignedExportEnvelope` used for
`SignedUnderwritingDecision`; these are re-exported directly as `canonical`,
`capability`, `crypto`, and `receipt`. Neither dependency is aliased. External:
`serde` for artifact (de)serialization. The crate does not depend on
`chio-kernel`; see Overview.
