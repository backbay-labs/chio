# chio-settle

`chio-settle` is the settlement runtime for Chio's official web3 contract
family. It turns approved Chio capital instructions into EVM or Solana
settlement actions, reconciles the on-chain result into the frozen web3
receipt schema, and exposes the CCIP cross-chain and payment-rail (x402,
EIP-3009, Circle, ERC-4337) compatibility surfaces built on top of it.

Use this crate to prepare, submit, and observe on-chain settlement, and to
route a signed Chio receipt through a `SettlementHook` implementation.
Contract artifact shapes and generated bindings live in `chio-web3` and
`chio-web3-bindings`; persistence lives in `chio-store-sqlite`; the kernel
dispatch path that produces the receipts this crate consumes lives in
`chio-kernel`.

## Responsibilities

- Prepare and validate EVM contract calls for escrow create/release/refund
  and bond lock/release/impair/expire, binding every call to the capital
  instruction, identity binding, and (for Merkle release) an anchor
  inclusion proof before it is ever submitted.
- Submit prepared calls, confirm transaction receipts, and finalize
  on-chain identity (escrow id, vault id) from emitted contract events.
- Assess finality (confirmations, dispute window, reorg) and project
  on-chain execution into a `Web3SettlementExecutionReceiptArtifact`.
- Prepare and reconcile the bounded Solana-native Ed25519 path and
  Chainlink CCIP cross-chain settlement messages.
- Prepare payment-rail compatibility artifacts: x402 payment requirements,
  EIP-3009 `transferWithAuthorization` digests, Circle nanopayments, and
  ERC-4337 paymaster sponsorship checks.
- Define the `SettlementHook` trait the kernel's post-dispatch observer
  slot calls, and the bounded retry/dead-letter envelope for its failures.
- Track operational state: emergency controls, indexer cursor health, lane
  runtime status, and watchdog automation jobs.

## Public API

By module (each re-exported from `lib.rs`):

- `hook` - `SettlementHook`, `SettlementObservation`, `SettlementOutcome`:
  the kernel post-dispatch extension point.
- `retry` - `RetryPolicy`, `classify_attempt`, `DeadLetterRecord`: bounded
  exponential backoff and dead-lettering for hook failures.
- `config` - `SettlementChainConfig`, `SettlementPolicyConfig`,
  `SettlementEvidenceConfig`, `SettlementOracleConfig`,
  `LocalDevnetDeployment`: chain wiring and amount-tier policy.
- `evm` - `prepare_web3_escrow_dispatch`, `prepare_merkle_release`,
  `prepare_dual_sign_release`, `prepare_bond_lock`/`prepare_bond_release`/
  `prepare_bond_impair`/`prepare_bond_expiry`, `submit_call`,
  `confirm_transaction`, `read_escrow_snapshot`, `read_bond_snapshot`,
  `finalize_escrow_dispatch`, `finalize_bond_lock`, and the
  `Prepared*`/`Evm*` wire types.
- `observe` - `inspect_finality`, `project_escrow_execution_receipt`,
  `observe_bond`: post-submission finality and lifecycle projection.
- `solana` - `prepare_solana_settlement`, `verify_solana_binding_and_receipt`,
  `compare_commitments`.
- `ccip` - `prepare_ccip_settlement_message`, `reconcile_ccip_delivery`.
- `payments` - `build_x402_payment_requirements`,
  `prepare_transfer_with_authorization`, `Eip3009NonceStore`,
  `evaluate_circle_nanopayment`, `prepare_paymaster_compatibility`.
- `automation` - `build_settlement_watchdog_job`, `build_bond_watchdog_job`,
  `assess_watchdog_execution`.
- `ops` - `SettlementEmergencyControls`, `SettlementControlState`,
  `SettlementRuntimeReport`, `classify_settlement_lane`,
  `ensure_settlement_operation_allowed`.

Crate root: `SettlementError`, `SettlementCommitment`,
`settlement_completion_flow_row_id`, `settlement_completion_flow_receipt_id`.

## Feature flags

| Flag | Effect |
|------|--------|
| `web3` (default) | Gates the entire crate body via `#![cfg(feature = "web3")]`. Building with no default features compiles this crate to nothing: no modules, no public items. |

## Testing

`cargo test -p chio-settle`

`tests/runtime_devnet.rs` and `tests/web3_e2e_qualification.rs` additionally
exercise a local Ganache devnet and the `contracts/` Node toolchain
(`ethers`, `ganache`); each test self-skips with a message when those
prerequisites are not on the machine.

## See also

- `chio-web3`, `chio-web3-bindings` - contract artifact shapes and the
  generated Solidity interfaces this crate calls.
- `chio-kernel` - wires `SettlementHook` into the post-dispatch observer slot.
- `chio-store-sqlite` - persists `DeadLetterRecord` rows in the
  `settle_dead_letters` table.
- `chio-egress-contract` - enforces the allowed RPC hosts and schemes for
  every chain RPC call this crate makes.
