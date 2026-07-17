# chio-credit

`chio-credit` defines Chio's credit, capital, and bonded-execution contracts: the
IOU envelope minted from a finalized receipt, the exposure ledger and credit
scorecard that summarize a subject's standing, the facility and bond artifacts
that grant and collateralize credit, and the capital book and capital-execution
instructions that gate custody-neutral fund movement against them. It composes
the appraisal and underwriting surfaces so credit decisions reference prior
signed Chio truth rather than restating it.

Use this crate to model credit limits, IOUs, and bonded execution for metered
tool access. Persistence and the HTTP surface live downstream, in
`chio-store-sqlite` and `chio-control-plane`.

## Responsibilities

- Define the credit-evaluator hook contract and signed IOU wire shape (`hook`),
  and ship the one implementation that mints IOUs: `local_account::LocalCreditAccount`,
  which re-verifies a finalized receipt before signing.
- Define the durable-store trait for IOU persistence (`store_binding::IouEnvelopeStore`);
  the SQLite implementation lives in `chio-store-sqlite`.
- Own the exposure ledger, credit scorecard, credit facility, and credit bond
  contracts (`lib.rs`): query/report/signed-artifact triples that project
  receipts and underwriting decisions into per-subject credit state.
- Own loss-lifecycle, backtest, and provider-risk-package report contracts
  (`risk_reports.rs`).
- Own capital book, capital-execution instruction, capital-execution authority,
  capital allocation, and bonded-execution-simulation contracts
  (`credit/capital_and_execution.rs` and its submodules), including the owning
  validator for capital-execution artifacts that downstream crates reuse
  instead of reimplementing.

## Public API

| Area | Key types |
|------|-----------|
| IOU hook (`hook`, `local_account`, `store_binding`) | `CreditEvaluatorHook`, `IouEnvelope`, `IouEnvelopeBody`, `CreditEvaluatorError`, `LocalCreditAccount`, `IouEnvelopeStore`, `IouEnvelopeStoreError` |
| Exposure ledger | `ExposureLedgerQuery`, `ExposureLedgerReport`, `SignedExposureLedgerReport` |
| Credit scorecard | `CreditScorecardReport`, `SignedCreditScorecardReport`, `CreditScorecardBand`, `CreditScorecardConfidence` |
| Credit facility | `CreditFacilityReport`, `CreditFacilityArtifact`, `SignedCreditFacility`, `CreditFacilityListQuery`, `CreditFacilityListReport` |
| Credit bond | `CreditBondReport`, `CreditBondArtifact`, `SignedCreditBond`, `CreditBondListQuery`, `CreditBondListReport` |
| Loss lifecycle (`risk_reports`) | `CreditLossLifecycleQuery`, `CreditLossLifecycleReport`, `CreditLossLifecycleArtifact`, `SignedCreditLossLifecycle`, `CreditLossLifecycleListQuery`, `CreditLossLifecycleListReport` |
| Backtesting (`risk_reports`) | `CreditBacktestQuery`, `CreditBacktestReport`, `CreditBacktestWindow` |
| Provider risk package (`risk_reports`) | `CreditProviderRiskPackageQuery`, `CreditProviderRiskPackage`, `SignedCreditProviderRiskPackage` |
| Capital book | `CapitalBookQuery`, `CapitalBookReport`, `SignedCapitalBookReport`, `CapitalBookSource`, `CapitalBookEvent` |
| Capital execution | `CapitalExecutionInstructionArtifact`, `SignedCapitalExecutionInstruction`, `validate_capital_execution_envelope`, `ensure_capital_execution_owner_authority`, `ensure_capital_execution_custodian_authority` |
| Capital execution authority | `CapitalExecutionAuthorityStep`, `validate_capital_execution_authority_step_proof` |
| Capital allocation | `CapitalAllocationDecisionArtifact`, `SignedCapitalAllocationDecision` |
| Bonded-execution simulation | `CreditBondedExecutionSimulationReport`, `CreditBondedExecutionControlPolicy`, `CreditBondedExecutionEvaluation` |

Every report and artifact carries a `schema` field pinned to a `pub const
*_SCHEMA` string (for example `IOU_ENVELOPE_SCHEMA`, `CREDIT_BOND_ARTIFACT_SCHEMA`)
for wire compatibility.

## Testing

`cargo test -p chio-credit`

## See also

- `chio-core-types` - supplies the `capability`, `crypto`, and `receipt` types
  these contracts build on and re-export.
- `chio-appraisal`, `chio-underwriting` - reputation and underwriting evidence
  these contracts reference rather than restate.
- `chio-core` - re-exports this crate as `chio_core::credit`; `chio-kernel`
  re-exports the capital-execution types and validator through that path.
- `chio-store-sqlite` - implements `IouEnvelopeStore` (`SqliteIouEnvelopeStore`)
  and builds the exposure, scorecard, facility, bond, and capital-book reports
  from receipt history.
- `chio-control-plane` - issues and lists these artifacts over HTTP, reusing
  the capital-execution validator via `chio-kernel` instead of reimplementing it.
