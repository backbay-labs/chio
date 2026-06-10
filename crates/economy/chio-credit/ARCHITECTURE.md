# chio-credit Architecture

## Boundaries

`chio-credit` owns Chio's credit, IOU, facility, bond, loss-lifecycle, capital-book, capital-instruction, and bonded-execution contract types. It is the economic contract crate: downstream control-plane and settlement code may build, sign, store, or dispatch these artifacts, but the reusable invariants for the artifacts belong here.

The main internal areas are:

- `hook.rs`: the finalized-receipt to IOU hook contract and signed IOU envelope wire shape.
- `local_account.rs`: in-memory IOU minting from signed kernel receipts.
- `store_binding.rs`: durable IOU persistence trait.
- `lib.rs`: exposure, scorecard, facility, and bond contracts.
- `risk_reports.rs`: loss-lifecycle, backtest, and provider-risk report contracts.
- `credit/capital_and_execution.rs`: capital-book, custody-neutral capital instruction, allocation decision, and bonded-execution simulation contracts.

## Capital Execution Envelope

The capital execution envelope is a load-bearing contract in the protocol: every capital instruction, reserve-control artifact, allocation decision, and liability capital movement depends on authority-chain freshness, execution-window validity, custody-provider authority, and amount reconciliation. The reusable validation for these artifacts is owned here so callers cannot construct and sign a `CapitalExecutionInstructionArtifact` through the public types without the owning-crate checks.

## Security And API Constraints

- Public data shapes and schema strings are stable for signed artifact compatibility.
- Capital semantics are fail-closed: stale authority, empty authority, expired windows, missing custody execution, invalid amounts, and contradictory observed execution reject before signing or dispatch.
- External custody execution is not ambient. Artifacts may describe intent or observed execution, but they do not imply automatic dispatch unless an explicit support boundary says so.
- `chio-credit` owns generic artifact validation; downstream code owns store lookups, source selection, web3 readiness, and HTTP status mapping.

## Validation Boundary

`credit/capital_and_execution.rs` exposes the owning-crate capital execution validation boundary. The validator covers authority chains, execution windows, custody-provider authority, capital rail identifiers, intended versus observed execution, cancel instruction shape, transfer receipt provenance, and nonzero amount rules. `chio-control-plane` reuses that validator through a thin status-mapping wrapper.

## Dependent Surfaces

Dependents are `chio-core` and `chio-kernel` reexports, `chio-control-plane` issuance paths, `chio-cli` request plumbing, `chio-store-sqlite` persistence/reporting, and `chio-settle` web3 dispatch readiness. Each calls the owning validator where artifacts are issued.

## Verification Focus

Tests should cover schema-string stability, signed IOU envelope compatibility,
capital instruction validation, stale or missing authority rejection, execution
window rejection, custody-provider authority mismatch, nonzero amount rules,
cancel instruction shape, transfer receipt provenance, and downstream
control-plane reuse of the owning validator.
