# Chio Web3 Profile

## Purpose

This profile freezes Chio's first official web3 settlement boundary. It defines
the trust profile, contract package, chain configuration, anchoring proof
bundle, oracle evidence envelope, settlement dispatch artifact, settlement
execution receipt, and qualification matrix that the official web3 stack must
honor.

> Version posture: this is a pre-release standards profile for the v1 protocol
> surface.

The packaged runtime realization includes:

- Solidity sources under `contracts/src/`
- compiled ABI and bytecode artifacts under `contracts/artifacts/`
- compiled interface artifacts under `contracts/artifacts/interfaces/`
- deployment manifests under `contracts/deployments/`
- artifact-derived Alloy bindings under `crates/economy/chio-web3-bindings/`
- local qualification evidence under `contracts/reports/`

The objective is specific: Chio can now reconcile one real external rail
execution path without allowing web3 adapters to replace canonical Chio truth,
hide custody assumptions, or widen trust through chain activity alone.

External assurance status: the contract package is not approved for mainnet
deployment, non-testnet custody, or non-testnet promotion. The local
qualification report and prior contract security review are historical evidence
only. External audit, testnet soak, artifact digest, runtime codehash,
minimum-bar checklist, and security-owner sign-off are required before
non-testnet use.

Bounded runtime overlays include:

- Functions-based Ed25519 fallback audits on EVM
- automation jobs for anchoring and settlement watchdog flows
- one CCIP settlement-coordination message family
- one explicit payment-interop layer for x402, EIP-3009, Circle, and
  ERC-4337/paymaster compatibility

Bounded operations overlays include:

- runtime reports across `chio-link`, `chio-anchor`, and `chio-settle`
- explicit emergency modes for anchor publication and settlement dispatch
- one deployment-promotion policy with gas and latency budgets
- one reviewer-facing external qualification matrix and partner-proof package

Runtime-hardening overlays include:

- concurrency-safe escrow and bond identity derived from contract truth rather
  than local mutable nonce state
- mandatory durable receipt storage, kernel-signed checkpoint issuance, and
  evidence-export gating for every claimed Merkle or Solana evidence lane
- explicit contract/runtime parity checks plus bond-reserve and oracle-
  authority reconciliation

Hosted-qualification overlays include:

- hosted release qualification that stages the bounded web3 bundle under
  `target/release-qualification/web3-runtime/`
- one reviewed-manifest deployment runner plus approval, promotion-report, and
  rollback-plan artifacts
- one generated end-to-end settlement proof bundle under
  `target/web3-e2e-qualification/` and the staged hosted `e2e/` copy

## Shipped Artifact Set

The official profile consists of these machine-readable artifacts:

- `chio.web3-trust-profile.v1`
- `chio.web3-contract-package.v1`
- `chio.web3-chain-configuration.v1`
- `chio.anchor-inclusion-proof.v1`
- `chio.oracle-conversion-evidence.v1`
- `chio.web3-settlement-dispatch.v2`
- `chio.web3-settlement-execution-receipt.v2`
- `chio.web3-qualification-matrix.v1`
- `chio.anchor-automation-job.v1`
- `chio.settlement-automation-job.v1`
- `chio.ccip-settlement-message.v1`
- `chio.web3-automation-qualification-matrix.v1`
- `chio.anchor-runtime-report.v1`
- `chio.settle-runtime-report.v1`

The corresponding reference files live in `docs/standards/`; the core web3
artifacts parse against `crates/core/chio-core`, while the runtime
overlay artifacts parse against the bounded types in `chio-anchor` and
`chio-settle`.

## Normative Boundary

- `did:chio` plus Ed25519 remains the root Chio identity surface; web3 key use
  is bound through explicit signed `chio.key-binding-certificate.v1` artifacts.
- The official stack is Base-first with Arbitrum as the bounded secondary
  deployment target; this profile does not claim arbitrary chain discovery.
- Chain anchors, checkpoint statements, and oracle envelopes reconcile back to
  canonical Chio receipts and capital artifacts; they never replace earlier
  signed Chio truth.
- `web3` is now a first-class `CapitalExecutionRailKind` and may appear in
  governed capital instructions and reconciled settlement receipts.
- Settlement lifecycle remains explicit. `pending_dispatch`, `escrow_locked`,
  `partially_settled`, `settled`, `reversed`, `charged_back`, `timed_out`,
  `failed`, and `reorged` are distinct states, not overloaded success flags.
- Custody, payment-institution, oracle-operator, and arbitrator assumptions
  remain explicit regulated-role declarations in the trust profile.
- Local policy activation remains mandatory. No web3 package, chain proof, or
  external execution implicitly becomes trusted by observation alone.
- Merkle and Solana evidence lanes are only claimed when Chio has local durable
  receipt storage plus kernel-signed checkpoint issuance; append-only remote
  receipt mirrors do not satisfy this boundary.
- Bitcoin secondary evidence is only claimed when the imported OpenTimestamps
  proof commits to the validated Chio super-root digest and attests the named
  Bitcoin height.
- Functions, automation, CCIP, and payment-interop overlays remain subordinate
  to the same canonical Chio receipt and settlement artifacts; they do not
  become a new truth source.

## Official Stack

The official package freezes one contract family:

- root registry
- escrow
- bond vault
- identity registry as the only owner-managed mutable contract in the package;
  it stays mutable because operator registration and key bindings change over
  time
- price resolver as an auxiliary on-chain reference contract only; runtime FX
  authority remains `chio-link`

The official chain configuration currently records historical target
references:

- Base (`eip155:8453`) as the primary execution and anchoring environment
- Arbitrum (`eip155:42161`) as the bounded secondary environment
- explicit addresses, operator identity, and gas assumptions for both chains.
  These are not promotion approval and remain blocked by external assurance.

This is a reviewable deployment model, not a permissionless contract
marketplace.

The current package is not uniformly immutable. Four contracts are immutable
(`root-registry`, `escrow`, `bond-vault`, and `price-resolver`), while the
identity registry remains owner-managed and mutable by design. Chio does not
claim proxy-free immutability for every contract surface.

## Settlement Model

The shipped dispatch and receipt surface claims only what Chio can verify:

- governed capital instructions authorize one real web3 settlement attempt
- dispatch artifacts bind that instruction to one escrow, one bond-vault
  contract, one beneficiary, and one support boundary
- execution receipts capture observed execution, settlement lifecycle, anchor
  reconciliation, and explicit `chio_link_runtime_v1` oracle evidence when
  cross-currency settlement paths require it
- Merkle-proof and dual-signature settlement paths are both modeled, but the
  official examples qualify the Merkle-proof path first
- FX-sensitive flows keep oracle provenance as an explicit side artifact rather
  than mutating the original receipt, and the optional `ChioPriceResolver`
  contract remains reference-only for contract-side review

## Runtime Extensions

The bounded runtime extensions over the official web3 stack are now:

- one audit-only Chainlink Functions fallback that batch-verifies already
  signed Chio receipts under explicit batch, gas, size, and notional ceilings
- one automation surface that schedules anchor publication and settlement or
  bond watchdog jobs under explicit replay windows, state fingerprints, and
  operator-override controls
- one CCIP message family that coordinates settlement state across chains and
  reconciles delivery back to canonical Chio execution receipts
- one payment-interop surface that projects governed settlement into x402,
  EIP-3009, Circle nanopayment, and ERC-4337 compatibility artifacts without
  mutating signed Chio truth

## Non-Goals

This profile does not claim:

- permissionless operator or contract discovery
- arbitrary cross-chain settlement routing beyond one bounded CCIP
  coordination message family
- autonomous pricing or reserve optimization
- ambient custody or regulated-actor status inferred from chain activity
- automatic fund release from Functions, automation, or paymaster execution
- public chain governance or universal dispute resolution

## Residual Public Gaps

The shipped boundary also keeps the following residual gaps explicit:

- local qualification is necessary but not sufficient for external
  publication; hosted `CI` and hosted `Release Qualification` remain required
- the identity registry is the one mutable contract in the official package;
  the public docs must not describe the entire contract family as immutable
- `ChioPriceResolver` remains a contract-side reference reader only; receipt-
  side FX authority stays with `chio-link`
- permissionless operator discovery, unattended mainnet rollout, and ambient
  MCP trust expansion remain outside the shipped public claim

Those surfaces belong to later reviewed package versions and must add their own bounded
artifacts rather than silently expanding this profile.
