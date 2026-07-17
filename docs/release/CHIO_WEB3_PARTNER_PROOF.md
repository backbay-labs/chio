# Chio Web3 Partner Proof Package

## Purpose

It is the compact reviewer-facing package for the bounded web3 stack: contracts,
oracle runtime, anchoring, settlement, interop overlays, runtime hardening,
hosted qualification, promotion, operator controls, and generated end-to-end
settlement proof.

> Version posture: this is a pre-release partner proof for the v1 protocol
> surface.

It is not the authoritative release-go record. Use
[RELEASE_AUDIT.md](RELEASE_AUDIT.md) for the repo-local release decision,
[RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md) for supported scope, and
[QUALIFICATION.md](QUALIFICATION.md) for the command/evidence contract.

## Current Decision

External assurance is required for the contract family. Local technical evidence
is rehearsal and partner-review context only.

External deployment, non-testnet custody, and non-testnet promotion remain
**blocked** until:

- external audit reports zero unresolved critical/high findings,
- testnet soak, artifact digest, runtime codehash, and minimum-bar gates
  pass,
- the security owner signs the assurance artifact for the exact approval,
  release, policy, and chain,
- hosted workflow results are observed on the candidate revision, including
  the staged bundle under `target/release-qualification/web3-runtime/`, and
- the operator approves the exact reviewed manifest, target-chain CREATE2
  factory, and rollout environment explicitly.

## What Reviewers Can Rely On

- one official non-proxy contract family where root registry, escrow, bond
  vault, and price resolver have fixed deployed bytecode, while identity
  registry, price feed admin, token allowlists, pause controls, delegates, and
  operator records remain explicit governed surfaces. This is a package-shape
  statement only; it is not mainnet approval.
- one bounded reviewed-manifest CREATE2 deployment runner that binds rollout
  to an exact manifest hash, release id, deployment policy id, and explicit
  rollback behavior
- one bounded `chio-link` runtime over pinned Base-first inventory, Chainlink
  primary, Pyth fallback, sequencer gating, and explicit operator pause state
- one bounded `chio-anchor` runtime over EVM root publication, imported
  OpenTimestamps and Solana memo secondary evidence, `did:chio` discovery, and
  fail-closed proof bundles that reject undeclared or digest-mismatched
  secondary lanes
- one bounded `chio-settle` runtime over escrow dispatch, anchored or
  dual-sign release, timeout refund, bond lifecycle observation, and explicit
  finality or reorg recovery projection, plus one generated end-to-end
  evidence package for FX-backed dual-sign execution and recovery posture
- one bounded Functions fallback, automation, CCIP coordination, and payment
  interop layer that remains subordinate to canonical Chio settlement truth
- one bounded web3 operations contract over runtime reports, drift classes,
  replay visibility, persisted control-state snapshots, append-only control
  traces, and emergency modes that narrow write authority rather than
  widening trust

## Promotion Gate Evidence

- `./scripts/qualify-web3-runtime.sh`
- `./scripts/qualify-web3-e2e.sh`
- `./scripts/qualify-web3-ops-controls.sh`
- `./scripts/qualify-web3-promotion.sh`
- `contracts/release/CHIO_WEB3_CONTRACT_RELEASE.json`
- `contracts/artifacts/ChioRootRegistry.json`
- `contracts/artifacts/ChioIdentityRegistry.json`
- `contracts/artifacts/ChioEscrow.json`
- `contracts/artifacts/ChioBondVault.json`
- `contracts/artifacts/ChioPriceResolver.json`
- `contracts/artifacts/interfaces/IChioRootRegistry.json`
- `contracts/artifacts/interfaces/IChioIdentityRegistry.json`
- `contracts/artifacts/interfaces/IChioEscrow.json`
- `contracts/artifacts/interfaces/IChioBondVault.json`
- `contracts/artifacts/interfaces/IChioPriceResolver.json`
- `contracts/deployments/base-mainnet.template.json`
- `contracts/deployments/base-sepolia.template.json`
- `contracts/deployments/arbitrum-one.template.json`
- `docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json`
- `docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_POLICY.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json`
- `docs/standards/CHIO_WEB3_OPERATOR_ENVIRONMENT.example`
- `docs/standards/CHIO_WEB3_OPERATIONS_PROFILE.md`
- `docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json`
- `docs/standards/CHIO_WEB3_EXTERNAL_QUALIFICATION_MATRIX.json`
- `docs/release/CHIO_WEB3_READINESS_AUDIT.md`
- `docs/release/CHIO_WEB3_OPERATIONS_RUNBOOK.md`
- `docs/release/CHIO_WEB3_DEPLOYMENT_PROMOTION.md`
- `spec/schemas/MANIFEST.sha256`
- `spec/schemas/chio-web3/v1/settlement-proof-bundle.schema.json`
- `target/release-qualification/web3-runtime/artifact-manifest.json`
- `target/release-qualification/web3-runtime/docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json`
- `target/release-qualification/web3-runtime/docs/standards/CHIO_WEB3_CHAIN_CONFIGURATION.json`
- `target/release-qualification/web3-runtime/spec/schemas/MANIFEST.sha256`
- `target/release-qualification/web3-runtime/logs/qualification.log`
- `target/release-qualification/web3-runtime/logs/e2e-qualification.log`
- `target/release-qualification/web3-runtime/logs/ops-qualification.log`
- `target/release-qualification/web3-runtime/logs/promotion-qualification.log`
- `target/release-qualification/web3-runtime/e2e/partner-qualification.json`
- `target/release-qualification/web3-runtime/e2e/scenarios/fx-dual-sign-settlement.json`
- `target/release-qualification/web3-runtime/e2e/scenarios/timeout-refund-recovery.json`
- `target/release-qualification/web3-runtime/e2e/scenarios/reorg-recovery.json`
- `target/release-qualification/web3-runtime/e2e/scenarios/bond-impair-recovery.json`
- `target/release-qualification/web3-runtime/e2e/scenarios/bond-expiry-recovery.json`
- `target/release-qualification/web3-runtime/ops/incident-audit.json`
- `target/release-qualification/web3-runtime/ops/runtime-reports/chio-link-runtime-report.json`
- `target/release-qualification/web3-runtime/ops/runtime-reports/chio-anchor-runtime-report.json`
- `target/release-qualification/web3-runtime/ops/runtime-reports/chio-settle-runtime-report.json`
- `target/release-qualification/web3-runtime/ops/control-state/chio-link-control-state.json`
- `target/release-qualification/web3-runtime/ops/control-state/chio-anchor-control-state.json`
- `target/release-qualification/web3-runtime/ops/control-state/chio-settle-control-state.json`
- `target/release-qualification/web3-runtime/ops/control-traces/chio-link-control-trace.json`
- `target/release-qualification/web3-runtime/ops/control-traces/chio-anchor-control-trace.json`
- `target/release-qualification/web3-runtime/ops/control-traces/chio-settle-control-trace.json`
- `target/release-qualification/web3-runtime/promotion/promotion-qualification.json`
- `target/release-qualification/web3-runtime/promotion/run-a/approval.json`
- `target/release-qualification/web3-runtime/promotion/run-a/promotion-report.json`
- `target/release-qualification/web3-runtime/promotion/run-a/rollback-plan.json`
- `target/release-qualification/web3-runtime/promotion/run-a/deployment.json`
- `target/release-qualification/web3-runtime/promotion/run-b/promotion-report.json`
- `target/release-qualification/web3-runtime/promotion/resume-existing/promotion-report.json`
- `target/release-qualification/web3-runtime/promotion/negative-approval/promotion-report.json`
- `target/release-qualification/web3-runtime/promotion/negative-rollback/promotion-report.json`
- `target/release-qualification/web3-runtime/promotion/negative-rollback/rollback-plan.json`

Cutover-only staged evidence is required when
`scripts/stage-web3-release-artifacts.sh --require-cutover-evidence` is used:

- `target/release-qualification/web3-runtime/live/base-sepolia/promotion/deployment.json`
- `target/release-qualification/web3-runtime/live/base-sepolia/promotion/promotion-report.json`
- `target/release-qualification/web3-runtime/live/base-sepolia/base-sepolia-smoke.json`
- `target/release-qualification/web3-runtime/live/base-sepolia/dependencies/dependencies.json`
- `target/release-qualification/web3-runtime/live/base-sepolia/dependencies/base-sepolia.review-inputs.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/review-result.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/summary.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/web3/validation-index.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/evidence/cutover-readiness.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/contracts/settlement-packet.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/contracts/web3-settlement-dispatch.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/contracts/web3-settlement-receipt.json`
- `target/release-qualification/web3-runtime/examples/internet-of-agents-web3-network/bundle-manifest.json`

## Historical Context

These artifacts may be staged under
`target/release-qualification/web3-runtime/historical/` when present, but they
are not promotion gate evidence and do not authorize testnet or non-testnet
promotion:

- `contracts/reports/local-devnet-qualification.json`
- `contracts/deployments/local-devnet.json`
- `contracts/deployments/local-devnet.reviewed.json`
- `contracts/reports/CHIO_WEB3_CONTRACT_SECURITY_REVIEW.md`
- `contracts/reports/CHIO_WEB3_CONTRACT_GAS_AND_STORAGE.md`

The local-devnet deployment JSON files may also appear in the staged bundle, but
only as deterministic devnet fixture metadata for reproducibility. They are not
promotion evidence.

## End-To-End Trace

Reviewers can trace one bounded runtime path end to end:

1. the official contract package, deployment templates, and reviewed-manifest
   promotion runner define the only supported contract rollout family
2. `chio-link` is the only supported runtime FX authority and provides explicit
   receipt-side evidence when cross-currency settlement is needed; the
   on-chain `ChioPriceResolver` contract is reference-only
3. `chio-anchor` publishes or verifies the checkpoint root that binds the
   release proof back to canonical Chio receipt truth
4. `chio-settle` dispatches or observes escrow and bond calls against the
   official contracts, keeps locked collateral distinct from reserve
   requirement metadata carried forward from signed bond artifacts, projects
   finality and recovery state back into Chio artifacts, and emits one
   generated partner-reviewable bundle for FX-backed dual-sign settlement plus
   refund, reorg, impair, and expiry recovery posture
5. the interop overlays may schedule, coordinate, or facilitate these flows,
   but they never replace the canonical settlement record
6. the generated ops runtime reports, control-state snapshots, control
   traces, and incident audit prove that emergency posture is exercised and
   reviewable instead of being a documentation-only claim
7. the staged `e2e/` bundle gives reviewers one compact settlement proof
   package instead of making them reconstruct dual-sign, FX-evidence, and
   recovery coverage from separate local tests

## Reviewer Caveats

- This package is partner-visible and reproducible, but it is still primarily
  local qualification evidence.
- The contract-family local qualification and old security review are
  historical evidence and are not promotion signals.
- The staged local-devnet deployment JSON is deterministic fixture metadata,
  not a testnet or non-testnet promotion signal.
- The repo does not yet claim unattended testnet or mainnet deployment.
- The repo does not yet claim public chain publication from local evidence
  alone.
- Deferred capabilities in
  `docs/standards/CHIO_WEB3_CONTRACT_PACKAGE.json`, including live mainnet
  transport expansions, remain deferred.
