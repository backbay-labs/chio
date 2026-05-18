# Chio Settle Operator Runbook

## Purpose

This runbook covers the supported operator actions for the shipped
`chio-settle` runtime originally tracked under internal milestone `v2.37`.

> Version posture: this is a pre-release operator runbook. Internal `v2.x`
> milestone labels are historical planning labels, not Chio-owned protocol,
> schema, SDK, or runtime versions. Current protocol posture is v1-only.

`chio-settle` is the bounded on-chain settlement surface. It does not discover
new rails permissionlessly, hold agent private keys, bridge funds between
chains, or automate dispute resolution without explicit operator review.

## Routine Checks

Before enabling a live settlement lane for an operator deployment:

1. Review the bounded runtime profile in
   `docs/standards/CHIO_SETTLE_PROFILE.md`.
2. Confirm the chain config pins the intended escrow, bond-vault, identity,
   and root-registry contract addresses.
3. Confirm the operator binding certificate still covers `settle` purpose and
   the intended chain scope.
4. Confirm the settlement token minor-unit decimals and the Chio
   amount-scaling policy still match the deployed token.
5. If Merkle-proof release is enabled, confirm `chio-anchor` is publishing and
   verifying the same operator namespace and root registry.
6. Run the local qualification commands:
   - `CARGO_TARGET_DIR=target/chio-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-settle -- --test-threads=1`
   - `CARGO_TARGET_DIR=target/chio-settle-runtime CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-settle --test runtime_devnet -- --nocapture`
   - `pnpm --dir contracts devnet:smoke`

## EVM Dispatch Lane

Use the EVM lane when the official escrow or bond-vault contracts are the
authoritative settlement rail.

Expected behavior:

- ERC-20 approval or equivalent allowance must exist before escrow or bond
  lock submission
- the runtime refuses dispatch when the capital instruction rail, destination,
  jurisdiction, or authority chain does not match the configured settlement
  lane
- the runtime estimates gas before submission and confirms the receipt instead
  of trusting the RPC send result alone

Recovery:

1. If approval or funding is missing, restore token allowance or source
   balance before retrying.
2. If static validation passes but the transaction fails on-chain, inspect the
   receipt, rebuild the preconditions, and only then retry submission.
3. If the runtime rejects the dispatch before submission, fix the authority,
   binding, or rail mismatch rather than bypassing the guard.

## Merkle-Proof Release

Use this path when settlement must be backed by anchored Chio receipt inclusion
proof.

Expected behavior:

- `chio-anchor` publishes the checkpoint root first
- `chio-settle` verifies the receipt inclusion proof against that same root
- the beneficiary release remains impossible without valid proof metadata

Recovery:

1. If proof verification fails, treat the release as denied and reconcile the
   checkpoint, receipt, and operator namespace before retrying.
2. If the transaction confirms but finality is still pending, wait for the
   configured confirmations and dispute window instead of treating the release
   as final immediately.
3. If canonical-chain block hash drift indicates a reorg, re-run proof and
   release preparation against the current canonical root before resubmission.

## Dual-Signature Release

Use this path when the runtime is operating on the EVM lane without Merkle
proof submission.

Expected behavior:

- the operator's registered settlement key signs the exact contract digest
- static validation rejects mismatched or outsider signatures
- the beneficiary remains the release caller; the operator signature alone does
  not move funds

Recovery:

1. If signature validation fails, rotate or re-register the settlement key
   through the identity registry before retrying.
2. If the binding certificate and registry key hash disagree, stop the lane
   until identity state is reconciled.

## Timeout, Refund, And Reorg Recovery

Expected behavior:

- expired escrows can be refunded by anyone after the deadline
- finality reports distinguish confirmation wait, dispute-window wait,
  finalized state, and reorg
- timeout and failure projections emit explicit Chio-side recovery actions

Recovery:

1. If an escrow expires unreleased, trigger the refund path and project the
   timeout state back into Chio truth.
2. If finality remains `awaiting_confirmations` or
   `awaiting_dispute_window`, do not mark the settlement complete yet.
3. If status becomes `reorged`, rebuild the settlement state against the new
   canonical chain and decide whether to resubmit or hold for manual review.

## Bond Lifecycle

Expected behavior:

- bond lock, release, impairment, and expiry are explicit transaction paths
- lifecycle observation distinguishes active, released, impaired, and expired
  vaults
- impairment or release remains an operator-controlled action, not an automatic
  hidden side effect

Recovery:

1. If a bond becomes impaired, stop treating it as healthy collateral and move
   the case into manual review.
2. If a bond expires without release, close it through the explicit expiry path
   rather than mutating local reserve state off-chain.

## Custody And Regulated-Role Notes

- The operator does not hold agent private keys. Agents or custodial
  counterparties remain responsible for wallet control.
- The escrow and bond-vault contracts are the fund-custody mechanism for this
  bounded lane; Chio remains the dispatch and reconciliation runtime, not the
  regulated custodian or insurer of record.
- Cross-currency conversion, if needed, comes from `chio-link`. Root
  publication comes from `chio-anchor`. `chio-settle` does not silently absorb
  those roles.
- Sanctions screening, legal review, and production wallet controls remain
  operator obligations outside this local qualification lane.
