# Chio Web3 Contract Security Review

> Historical review only as of 2026-07-04. This file is not a promotion signal
> and does not authorize mainnet deployment, non-testnet custody, or
> non-testnet promotion. Current contract review evidence must include
> independent adversarial review. Confirmed critical/high blockers:
> `F1-root-forgery`, `F3-settlement-replay`,
> `escrow-proof-release-unbound`, `F2-unbound-commitments`,
> `F4-delegate-brick`, `bondvault-impair-reentrancy-slash-cap-bypass`,
> `CHIO-AC-01`, and `no-emergency-stop-deactivation-ineffective`.
> Promotion remains blocked until external audit, testnet soak, artifact
> digest, runtime codehash, and minimum-bar checks pass with security-owner
> sign-off.

## Scope

This review covers the official Chio web3 contract family:

- `ChioIdentityRegistry`
- `ChioRootRegistry`
- `ChioEscrow`
- `ChioBondVault`
- `ChioPriceResolver`

## Positive Findings

- Fail-closed proof semantics
  - The legacy under-specified proof entrypoints (`releaseWithProof`,
    `partialReleaseWithProof`, `releaseBond`, `impairBond`, and
    `verifyInclusion`) revert instead of guessing missing RFC6962 metadata.
- Explicit operator binding
  - Root publication and escrow creation require the registered operator
    Ed25519 key hash to match the identity registry.
- Bounded delegate publication
  - Root publication supports explicit delegate registration, bounded to three
    active delegates per operator, with immediate revocation.
- Signature scope tightening
  - `releaseWithSignature` binds `chainid`, escrow contract address, escrow id,
    receipt hash, and settled amount into the signed digest.
- No admin override on fund release
  - Escrow and bond state transitions do not expose admin-controlled release or
    slash bypasses.
- Sequencer and staleness controls
  - `ChioPriceResolver` rejects stale feed data and sequencer-down conditions.
- Explicit collateral boundary
  - `ChioBondVault` only locks `collateralAmount` on-chain. The reserve
    requirement fields preserved in bond terms are metadata for parity with
    signed Chio bond artifacts, not a second spendable balance.
- Auxiliary price-reference scope
  - `ChioPriceResolver` is an optional contract-side reference reader. Kernel
    FX charging and receipt-side oracle evidence remain authoritative only
    through `chio-link`.

## Residual Risks and Non-Goals

- No on-chain Ed25519 verification
  - Identity binding remains an off-chain registration ceremony backed by the
    registry admin and emitted proof material.
- No sanctioned-address or blacklist screening
  - The contracts do not yet integrate USDC blacklist checks or address
    screening before escrow or bond creation.
- No relayer registry
  - Escrow release is beneficiary-driven today. The research discussed
    beneficiary-or-relayer authorization, but a relayer allowlist is not part
    of the current runtime surface.
- Live CREATE2 deploy script is assurance-gated
  - This historical review predates the current reviewed-manifest runner.
    `contracts/scripts/promote-deployment.mjs` now covers deterministic
    CREATE2 execution, but non-testnet use remains blocked on target-specific
    approval and external assurance evidence.
- No proxy upgrade path
  - This is intentional, but it means defect fixes require replacement
    deployments and config migration rather than in-place upgrades.

## Reviewed Invariants

- Unauthorized or revoked publishers cannot anchor roots.
- Root checkpoint sequence must increase strictly per operator.
- Escrow release cannot exceed deposited balance.
- Escrow refund cannot happen before deadline.
- Bond release and impairment require explicit detailed proof input.
- Price reads fail closed on stale or sequencer-down inputs.

## Qualification Evidence

- `contracts/reports/local-devnet-qualification.json`
- `contracts/deployments/local-devnet.json`
- `contracts/scripts/qualify-devnet.mjs`
