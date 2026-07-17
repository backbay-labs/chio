# chio-credit architecture

## Overview

`chio-credit` is a pure contract and validation crate for Chio's credit
economy: IOU envelopes, exposure ledgers, credit scorecards, facilities,
bonds, loss lifecycle, backtests, provider risk packages, and capital
execution. It performs no network or disk I/O and forbids unsafe code
(`#![forbid(unsafe_code)]`); the one piece of live behavior it owns is
`local_account::LocalCreditAccount`, which independently re-verifies a
kernel-signed `ChioReceipt` (signature, content-addressed id, action hash,
signer trust) before minting a signed IOU, rather than trusting a caller's
claim that the receipt is valid. Persistence, HTTP surfacing, and capital
dispatch belong to downstream crates (`chio-store-sqlite`, `chio-control-plane`,
`chio-settle`); this crate owns the wire shapes and the fail-closed validation
those crates reuse, most notably the capital-execution authority-chain
validator that `chio-kernel` and `chio-control-plane` both call through
instead of duplicating.

## Module map

`src/credit/capital_and_execution.rs` is spliced into `lib.rs` with `include!`,
not declared as `pub mod credit`. Every type it and its `#[path]` children
re-export is therefore a crate-root item (`chio_credit::CapitalBookQuery`,
never `chio_credit::credit::...`), on the same footing as the types defined
directly in `lib.rs`.

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Crate root: exposure ledger, credit scorecard, credit facility, and credit bond contracts; re-exports `chio-core-types::{capability, crypto, receipt}`, `chio-appraisal`, and `chio-underwriting`; `include!`s `credit/capital_and_execution.rs`. |
| `src/hook.rs` | `CreditEvaluatorHook` trait and the signed `IouEnvelope` / `IouEnvelopeBody` wire shape. |
| `src/local_account.rs` | `LocalCreditAccount`, the only `CreditEvaluatorHook` implementation in this crate: deterministic, signature-verified IOU minting. |
| `src/store_binding.rs` | `IouEnvelopeStore` durable-persistence trait. |
| `src/risk_reports.rs` | Loss-lifecycle, backtest, and provider-risk-package report contracts. |
| `src/credit/capital_and_execution.rs` | Declares and re-exports the six capital submodules below; `#[cfg(test)]`-includes `tests.rs`. |
| `src/credit/capital_and_execution/capital_book.rs` | Capital book source and event contracts. |
| `src/credit/capital_and_execution/capital_execution.rs` | `CapitalExecutionInstructionArtifact` and the owning capital-execution validator. |
| `src/credit/capital_and_execution/capital_allocation.rs` | `CapitalAllocationDecisionArtifact`. |
| `src/credit/capital_and_execution/bonded_execution.rs` | Bonded-execution control policy, evaluation, and simulation report. |
| `src/credit/capital_book_query.rs` | `CapitalBookQuery`, the cross-cutting query for capital book / execution / allocation reports. |
| `src/credit/capital_execution_authority.rs` | `CapitalExecutionAuthorityStep` and signed authority-step-proof verification. |

## IOU minting

1. A kernel-signed `ChioReceipt` is passed to `CreditEvaluatorHook::evaluate`.
2. `LocalCreditAccount::evaluate` verifies the receipt's signature, recomputes
   its content-addressed id, verifies the action-parameter hash, and checks
   the embedded kernel key against the account's trusted-kernel-key set; any
   failure returns `Err` and mints nothing.
3. Receipts that are not `Allow`, carry no financial metadata, or have
   `cost_charged == 0` evaluate to `Ok(None)`.
4. Otherwise the account builds an `IouEnvelopeBody`, derives `iou_id`
   deterministically from the receipt id (`iou-` plus the first 32 hex
   characters of its SHA-256), signs the canonical body, and returns one
   `IouEnvelope`.
5. The caller persists the envelope through an `IouEnvelopeStore`
   implementation; production uses `chio-store-sqlite::SqliteIouEnvelopeStore`.

Steps 2-4 are pure over `(receipt, trusted key set)`, so re-evaluating the same
receipt reproduces a byte-identical envelope. `tests/iou_invariants.rs`
property-tests that, plus the zero-or-one-IOU invariant, across receipt
decision, pricing, and tampering scenarios.

## Invariants and failure modes

- IOU minting fails closed: signature-invalid receipts, action-hash mismatches,
  and untrusted kernel keys all return `Err`; nothing is minted or persisted
  from a rejected receipt.
- `IouEnvelopeStore::insert` is idempotent per `receipt_id`: a byte-identical
  re-insert returns `Ok(false)`, and a conflicting envelope for the same
  `receipt_id` returns `Err(IouEnvelopeStoreError::Conflict)` rather than
  overwriting it.
- `validate_capital_execution_envelope` is the single owning validator for
  capital-execution artifacts: a non-empty authority chain, non-empty rail and
  custody-provider ids, `not_before <= not_after` on an unexpired execution
  window, and per-step bounds (`approved_at <= expires_at`,
  `approved_at <= issued_at`, `expires_at >= issued_at`,
  `expires_at >= execution_window.not_after`) with a verified signed proof on
  every step, plus one step in the `Custodian` role whose `principal_id`
  matches the rail's `custody_provider_id`. `chio-kernel` re-exports this
  function and the owner/custodian authority helpers rather than
  reimplementing them, and `chio-control-plane` wraps that re-export with a
  thin status-mapping layer.
- `CapitalExecutionInstructionArtifact::validate` adds action-shaped rules:
  `transfer_funds` requires `source_kind = facility_commitment` plus a
  governed receipt id and completion-flow row id; reserve actions
  (`lock_reserve` / `hold_reserve` / `release_reserve`) require
  `source_kind = reserve_book` and forbid that provenance; `cancel_instruction`
  carries no amount or observed execution and requires a
  `related_instruction_id`; every other action requires a positive amount.
- Observed capital execution reconciles fail-closed in both directions: an
  `observed_execution` requires a matching amount, a timestamp inside the
  execution window, and `reconciled_state = matched`; its absence requires
  `reconciled_state = not_observed`.
- Every report and artifact carries an explicit `*SupportBoundary` struct
  (`ExposureLedgerSupportBoundary`, `CreditBondSupportBoundary`,
  `CapitalExecutionInstructionSupportBoundary`, and others) whose booleans
  state what is authoritative versus merely described; none imply automatic
  external dispatch.
- Subject-scoped queries fail validation without their anchor:
  `CreditBacktestQuery`, `CreditProviderRiskPackageQuery`, and
  `CapitalBookQuery` each require `agent_subject` on top of
  `ExposureLedgerQuery`'s at-least-one-anchor rule; `CreditLossLifecycleQuery`
  requires a non-empty `bond_id` (and a strictly positive `amount` when
  present); `CreditBondedExecutionSimulationQuery` requires a non-empty
  `bond_id`.

## Dependencies

- `chio-core-types` (re-exported as `capability`, `crypto`, `receipt`)
  supplies `MonetaryAmount`, `GovernedAutonomyTier`, `RuntimeAssuranceTier`,
  `Decision`, `SettlementStatus`, `SignedExportEnvelope`, `ChioReceipt`, and
  the signing and hashing primitives the mint path and every contract use.
- `chio-appraisal` (re-exported as `appraisal`) supplies
  `AttestationVerifierFamily` for scorecard and provider-risk-package
  runtime-assurance evidence.
- `chio-underwriting` (re-exported as `underwriting`) supplies the decision
  lifecycle, outcome, review, risk-class, certification, and compliance types
  exposure and facility contracts reference instead of restating.
- `serde` / `serde_json` for wire (de)serialization; `thiserror` for the hook
  and store error enums.
- Dev-only: `proptest` backs `tests/iou_invariants.rs`.

## Extension points

- `CreditEvaluatorHook` - implement to mint IOUs under another rule than
  `LocalCreditAccount`'s; dyn-compatible (`&dyn CreditEvaluatorHook`).
- `IouEnvelopeStore` - implement to persist envelopes on another backend;
  `chio-store-sqlite::SqliteIouEnvelopeStore` is the shipped implementation.
