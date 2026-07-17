# chio-autonomy

`chio-autonomy` defines Chio's bounded autonomous insurance-automation
contracts: pricing, capital-pool optimization, execution, rollback, drift,
and comparison artifacts, each with a fail-closed validator. The crate is
pure data and validation; it performs no I/O and holds no runtime state.

Every artifact stays evidence-referential: pricing and execution decisions
embed or cite by id the prior underwriting, capital, market, and web3 truth
that justifies them, rather than asserting new authority on their own.
`chio-core` re-exports this crate as `autonomy`.

## Responsibilities

- Model ten `chio.autonomous-*` / `chio.capital-pool-*` wire artifacts (see
  Public API) as serde structs, plus a `Signed<Name>` envelope alias for
  each.
- Validate each artifact fail-closed: schema id, required/non-empty fields,
  duplicate and unknown references, and 3-letter uppercase currency codes
  matched by exact string comparison (no case-folding or trimming).
- Bound automation to its declared authority: suggested coverage/premium
  capped by the authority envelope, bind gated on `live_bind_supported` and
  `permitted_actions`, shadow automation forced into `review_state:
  ShadowOnly`, and auto-approval blocked above the envelope's human-review
  premium threshold.
- Enforce execution and drift safety: `lifecycle_state: Executed` requires
  every safety gate to pass, `Blocked` requires at least one to fail, and a
  `Critical` drift signal requires both `fail_safe_engaged` and a matching
  trigger in the paired rollback plan.
- Report every violation through `AutonomyContractError`, a closed
  `thiserror` enum.

## Public API

One wire artifact and one validator per autonomy contract (`model.rs` /
`validation.rs`):

| Artifact | Validator |
|---|---|
| `AutonomousPricingInputArtifact` | `validate_autonomous_pricing_input` |
| `AutonomousPricingAuthorityEnvelopeArtifact` | `validate_autonomous_pricing_authority_envelope` |
| `AutonomousPricingDecisionArtifact` | `validate_autonomous_pricing_decision` |
| `CapitalPoolOptimizationArtifact` | `validate_capital_pool_optimization` |
| `CapitalPoolSimulationReport` | `validate_capital_pool_simulation_report` |
| `AutonomousExecutionDecisionArtifact` | `validate_autonomous_execution_decision` |
| `AutonomousRollbackPlanArtifact` | `validate_autonomous_rollback_plan` |
| `AutonomousComparisonReport` | `validate_autonomous_comparison_report` |
| `AutonomousDriftReport` | `validate_autonomous_drift_report` |
| `AutonomousQualificationMatrix` | `validate_autonomous_qualification_matrix` |

Each artifact has a `Signed<Name>` alias for `SignedExportEnvelope<Name>`
(from `chio_core_types::receipt::lineage`), e.g.
`SignedAutonomousPricingDecision`.

`AutonomousEvidenceReference` (`kind: AutonomousEvidenceKind`,
`reference_id`, optional `observed_at` / `locator`) is the pointer type
pricing input, explanation factors, and drift signals use to cite evidence
from other crates. `AutonomousEvidenceKind` has 11 variants spanning
underwriting, credit, capital, liability-market, web3-settlement, claim, and
runtime-assurance evidence.

Also exported: `AutonomyContractError`; re-exports `capability`, `receipt`
(from `chio-core-types`), `market` (`chio-market`), `web3` (`chio-web3`)
used by artifact fields.

## Testing

`cargo test -p chio-autonomy` runs `src/tests.rs` (fixture builders and
validator regression tests) and `tests/integration_smoke.rs` (a public-API
smoke test). One unit test, `reference_artifacts_parse_and_validate`,
deserializes and validates every reference example under
`docs/standards/CHIO_AUTONOMOUS_*.json` and
`docs/standards/CHIO_CAPITAL_POOL_*.json`.

## See also

- `docs/standards/CHIO_AUTONOMOUS_PRICING_PROFILE.md` - the bounded-claim
  spec these artifacts implement.
- `chio-core` - re-exports this crate as `autonomy`.
- `chio-market`, `chio-web3` - supply `LiabilityCoverageClass` and
  `Web3SettlementLifecycleState` used in artifact fields.
