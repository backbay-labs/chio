# Chio Web3 Interop Runbook

## Purpose

This runbook covers the supported operator actions for web3 automation,
transport, and payment-interop surfaces originally tracked under internal
milestone `v2.38`.

> Version posture: this is a pre-release operator runbook. Internal `v2.x`
> milestone labels are historical planning labels, not Chio-owned protocol,
> schema, SDK, or runtime versions. Current protocol posture is v1-only.

These lanes are bounded overlays on top of `chio-link`, `chio-anchor`, and
`chio-settle`. They do not replace those runtimes or widen Chio truth from
external scheduler, DON, bridge, or facilitator behavior.

## Routine Checks

Before enabling any web3 interop surface:

1. Review `docs/standards/CHIO_FUNCTIONS_FALLBACK_PROFILE.md`,
   `docs/standards/CHIO_AUTOMATION_PROFILE.md`,
   `docs/standards/CHIO_CCIP_PROFILE.md`, and
   `docs/standards/CHIO_PAYMENT_INTEROP_PROFILE.md`.
2. Confirm the operator still intends the bounded Base-first chain inventory
   and the official contract package.
3. Confirm every enabled surface keeps direct fund movement subordinate to the
   explicit `chio-settle` lane.
4. Re-run the local qualification commands:
   - `CARGO_TARGET_DIR=target/chio-anchor-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-anchor -- --test-threads=1`
   - `CARGO_TARGET_DIR=target/chio-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-settle --lib -- --test-threads=1`
   - `CARGO_TARGET_DIR=target/chio-settle-runtime CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p chio-settle --test runtime_devnet -- --nocapture`

## Functions Fallback

Use the Functions lane only for audit or spot-check verification when the EVM
environment cannot natively verify the required Ed25519 material.

Expected behavior:

- Chio verifies receipts locally before request preparation
- the request stays within bounded batch, size, gas, and notional ceilings
- a verified DON response still cannot authorize direct fund release

Recovery:

1. If the DON response is rejected, unsupported, or mismatched, treat the
   fallback as failed and keep the proof path local-only.
2. If request size or callback gas grows beyond the bounded policy, split the
   audit batch or deny the fallback rather than widening the policy ad hoc.

## Automation Jobs

Use automation only for bounded anchor publication and settlement or bond
watchdog observation.

Expected behavior:

- state fingerprints remain stable from scheduling to execution
- delayed or duplicate execution is recorded explicitly
- operator override remains available for the shipped jobs

Recovery:

1. If the observed fingerprint drifts, invalidate the job and rebuild it from
   fresh chain or dispatch state.
2. If a job fires after the replay window, keep it informational unless the
   execution is explicitly marked `delayed_but_safe`.

## CCIP Coordination

Use CCIP only for the bounded settlement-coordination message family.

Expected behavior:

- the destination chain and payload hash match the prepared message exactly
- validity windows remain at least twice the configured latency budget
- duplicate or delayed deliveries are surfaced explicitly

Recovery:

1. If delivery arrives on the wrong chain or with the wrong payload hash,
   reject it and keep the canonical Chio receipt authoritative.
2. If delivery is duplicated, suppress the duplicate and investigate the relay
   path before retrying.
3. If delivery is late, keep the result explicit as delayed instead of
   projecting a normal successful handoff.

## Payment Interop

Use x402, Circle, EIP-3009, and ERC-4337 compatibility only when the operator
has already accepted the explicit settlement and custody posture.

Expected behavior:

- x402 carries one explicit facilitator URL, resource, token allowlist, and
  governed dispatch reference
- Circle nanopayments remain bounded to explicit operator-managed custody
- ERC-4337 paymaster use remains within bounded gas and reimbursement policy
- any sponsored gas deduction stays explicit in settlement review

Recovery:

1. If a facilitator, custody, or paymaster policy becomes ambiguous, disable
   the interop lane and continue using the canonical settlement path.
2. If sponsorship exceeds policy or the requested chain is unsupported,
   reject the compatibility request rather than silently degrading policy.

## Supported Recovery Boundary

`v2.38` interop recovery is complete when:

- the underlying `chio-link`, `chio-anchor`, and `chio-settle` lanes are healthy
- every enabled interop surface still matches its bounded profile
- the local qualification commands and JSON checks are green

If those conditions are not met, Chio should continue failing closed for the
affected interop surface.
