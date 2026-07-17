# chio-autonomy architecture

## Overview

`chio-autonomy` is a pure protocol crate: in-memory artifact types and
fail-closed validators, no I/O, no runtime state, `#![forbid(unsafe_code)]`.
It sits in the economy layer of the dependency graph, drawing field types
from the market and web3 domain crates below it and re-exported by
`chio-core` (as `autonomy`) above it. The design idea is bounded,
evidence-referential automation: every autonomous pricing or execution
artifact embeds or cites by id the prior signed Chio truth that justifies
it, and validation enforces that the artifact never asserts more authority
than its authority envelope grants.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API root. Re-exports `capability`/`receipt` (`chio-core-types`), `market` (`chio-market`), `web3` (`chio-web3`), and declares `error`, `model`, `validation`. |
| `src/model.rs` | Schema-id constants, enums, and the wire-artifact structs for all ten autonomy contracts, plus their `Signed<Name>` envelope aliases. |
| `src/validation.rs` | One fail-closed validator per artifact, plus shared helpers (`ensure_non_empty`, `ensure_unique_strings`, `ensure_unique_copy_values`, `validate_currency_code`, `money_currency_matches_declared`, `validate_positive_money`). |
| `src/error.rs` | `AutonomyContractError`, the closed validation-error enum. |
| `src/tests.rs` (`cfg(test)`) | Fixture builders and validator regression tests, excluded from the public build. |

## Artifact lineage

The autonomy contracts form a reference chain, not a runtime pipeline (the
crate does not execute or resolve anything itself):

1. `AutonomousPricingInputArtifact` cites upstream evidence by
   `AutonomousEvidenceReference` / `AutonomousEvidenceKind`.
2. `AutonomousPricingDecisionArtifact` embeds its
   `AutonomousPricingInputArtifact` and
   `AutonomousPricingAuthorityEnvelopeArtifact` in full; validating the
   decision validates both nested artifacts.
3. `CapitalPoolOptimizationArtifact` and `AutonomousExecutionDecisionArtifact`
   instead cite the decision and each other by opaque `..._ref: String` id
   (`pricing_decision_ref`, `optimization_ref`, `authority_envelope_ref`,
   `rollback_plan_ref`, and similar); this crate does not resolve those ids.
4. `CapitalPoolSimulationReport` and `AutonomousDriftReport` embed their
   nested artifacts (baseline/candidate optimizations; rollback plan and
   comparison report) and validate them inline.

Consumers hold the receipt store or evidence index that resolves the
id-only references.

## Invariants and failure modes

- Every validator checks schema id, then required/non-empty fields, then
  duplicate identifiers, before any cross-field rule.
- Currency matching is exact string equality
  (`money_currency_matches_declared`): a padded or lowercase currency code
  fails validation rather than being normalized.
- An authority envelope permits `Bind` only when `automation_mode ==
  Active`; `RegulatedRole` and `DelegatedMarketAuthority` kinds each require
  their own reference field; `not_before` must precede `not_after`; a
  premium review threshold cannot exceed `max_premium_amount`.
- A pricing decision's suggested coverage/premium must stay inside the
  authority envelope's ceilings and share its subject/provider/currency.
  `review_state: ShadowOnly` and `automation_mode: Shadow` require each
  other. `disposition: BindWithinEnvelope` additionally requires bind
  permission, `live_bind_supported`, and (when the envelope requires it)
  that the decision is not auto-approved.
- A capital-pool simulation's baseline and candidate optimizations must
  share `subject_key` and `currency`, carry distinct `optimization_id`s, and
  both have `scenario_comparison_supported`. A `ShiftCapacity`
  recommendation requires `destination_ref`.
- `AutonomousExecutionDecisionArtifact` requires every safety gate to pass
  before `lifecycle_state: Executed`, at least one to fail before `Blocked`,
  and action-specific references (`Bind` requires `quote_response_ref`,
  `auto_bind_decision_ref`, `bound_coverage_ref`, and
  `settlement_dispatch_ref` once executed; `Reprice`/`Renew`/`Decline`
  forbid the bind and settlement references).
- A `Critical` drift signal requires `fail_safe_engaged` on the report and a
  matching entry in the paired rollback plan's `triggers`. Rollback plan
  `triggers` and `actions` must each be non-empty and duplicate-free.
- A qualification matrix requires at least one case; each case needs a
  unique `id` and at least one `requirement_ids` entry.
- Support-boundary defaults diverge by risk: `AutonomousPricingSupportBoundary::default()`
  sets all four requirement/support flags `true` (an unset boundary assumes
  the strictest posture). `CapitalPoolOptimizationSupportBoundary::default()`
  is shadow-safe instead: `live_mutation_supported` and
  `cross_currency_optimization_supported` default `false`, while
  `web3_reconciliation_required` and `operator_override_required` default
  `true`.

## Dependencies

Internal: `chio-core-types` supplies `capability` (`MonetaryAmount`,
`RuntimeAssuranceTier`) and `receipt::lineage::SignedExportEnvelope`,
re-exported here as `capability` and `receipt`. `chio-market` supplies
`LiabilityCoverageClass`, re-exported as `market`. `chio-web3` supplies
`Web3SettlementLifecycleState`, re-exported as `web3`. No dependency is
aliased under a different package name. External: `serde`/`serde_json` for
artifact (de)serialization, `thiserror` for `AutonomyContractError`.

Only `chio-core` depends on this crate (re-exported as `autonomy`).
`chio-market` and `chio-web3` do not depend back on it, avoiding a cycle
through `chio-core`.
