# chio-credit Architecture

## Boundaries

`chio-credit` owns Chio's credit, IOU, facility, bond, loss-lifecycle, capital-book, capital-instruction, and bonded-execution contract types. It is the economic contract crate: downstream control-plane and settlement code may build, sign, store, or dispatch these artifacts, but the reusable invariants for the artifacts belong here.

The main internal areas are:

- `hook.rs`: the finalized-receipt to IOU hook contract and signed IOU envelope wire shape.
- `local_account.rs`: in-memory IOU minting from signed kernel receipts.
- `store_binding.rs`: durable IOU persistence trait.
- `lib.rs`: exposure, scorecard, facility, bond, loss-lifecycle, backtest, and provider-risk report contracts.
- `credit/capital_and_execution.rs`: capital-book, custody-neutral capital instruction, allocation decision, and bonded-execution simulation contracts.

## Pain Points

The capital execution envelope is a load-bearing contract in the protocol: every capital instruction, reserve-control artifact, allocation decision, and liability capital movement depends on authority-chain freshness, execution-window validity, custody-provider authority, and amount reconciliation. Today those checks are implemented downstream in `chio-control-plane`, while `chio-credit` only exposes the structs.

That split weakens the crate boundary. A caller can construct and sign a `CapitalExecutionInstructionArtifact` directly through the public types without any owning-crate validation, and downstream modules have to duplicate or remember the economic invariants themselves.

## Security And API Constraints

- Preserve public data shapes and schema strings for signed artifact compatibility.
- Preserve fail-closed capital semantics: stale authority, empty authority, expired windows, missing custody execution, invalid amounts, and contradictory observed execution must reject before signing or dispatch.
- Do not make external custody execution ambient. Artifacts may describe intent or observed execution, but they must not imply automatic dispatch unless an explicit support boundary says so.
- Keep control-plane and settlement transitive edits minimal. `chio-credit` should own generic artifact validation; downstream code can still own store lookups, source selection, web3 readiness, and HTTP status mapping.

## Affected Dependents

Primary dependents are `chio-core` and `chio-kernel` reexports, `chio-control-plane` issuance paths, `chio-cli` request plumbing, `chio-store-sqlite` persistence/reporting, and `chio-settle` web3 dispatch readiness. The validation boundary preserves struct compatibility and only moves reusable validation into this crate, so dependent changes should be limited to calling the owning validator where artifacts are issued.

## Validation Boundary

`credit/capital_and_execution.rs` exposes the owning-crate capital execution validation boundary. The validator covers authority chains, execution windows, custody-provider authority, capital rail identifiers, intended versus observed execution, cancel instruction shape, transfer receipt provenance, and nonzero amount rules. `chio-control-plane` reuses that validator through a thin status-mapping wrapper instead of keeping the generic economic contract checks as downstream-only logic.

## Verification Focus

Tests should cover schema-string stability, signed IOU envelope compatibility,
capital instruction validation, stale or missing authority rejection, execution
window rejection, custody-provider authority mismatch, nonzero amount rules,
cancel instruction shape, transfer receipt provenance, and downstream
control-plane reuse of the owning validator.
