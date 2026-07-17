# Chio Web3 Operations Profile

## Purpose

This profile closes phases `165` and `175` by freezing the bounded
production-operations surface for Chio's shipped web3 runtime stack.

It covers four connected surfaces:

- the existing `chio-link` runtime monitor and pause-control report
- the new `chio-anchor` runtime report for indexer drift, replay, and
  publication recovery
- the new `chio-settle` runtime report for finality, reorg recovery, and
  refund-first emergency posture
- persisted control-state snapshots and ordered control traces for each web3
  runtime
- the qualification matrix proving these operations surfaces fail closed

## Shipped Operations Boundary

Chio now claims one bounded web3 operations contract only:

- one oracle runtime report under `chio.link.runtime-report.v1`
- one anchor runtime report under `chio.anchor-runtime-report.v1`
- one settlement runtime report under `chio.settle-runtime-report.v1`
- explicit indexer status classes: `healthy`, `lagging`, `drifted`,
  `replaying`, and `failed`
- explicit emergency modes that can narrow the writable runtime surface
  without widening trust or mutating prior signed Chio truth

## Machine-Readable Artifacts

- `target/web3-ops-qualification/runtime-reports/chio-link-runtime-report.json`
- `target/web3-ops-qualification/runtime-reports/chio-anchor-runtime-report.json`
- `target/web3-ops-qualification/runtime-reports/chio-settle-runtime-report.json`
- `target/web3-ops-qualification/control-state/chio-link-control-state.json`
- `target/web3-ops-qualification/control-state/chio-anchor-control-state.json`
- `target/web3-ops-qualification/control-state/chio-settle-control-state.json`
- `target/web3-ops-qualification/control-traces/chio-link-control-trace.json`
- `target/web3-ops-qualification/control-traces/chio-anchor-control-trace.json`
- `target/web3-ops-qualification/control-traces/chio-settle-control-trace.json`
- `target/web3-ops-qualification/incident-audit.json`
- `docs/standards/CHIO_WEB3_OPERATIONS_QUALIFICATION_MATRIX.json`

Schema-reference examples remain checked in under `docs/standards/`:

- `docs/standards/CHIO_LINK_MONITOR_REPORT_EXAMPLE.json`
- `docs/standards/CHIO_ANCHOR_RUNTIME_REPORT_EXAMPLE.json`
- `docs/standards/CHIO_SETTLE_RUNTIME_REPORT_EXAMPLE.json`

## Indexers And Drift

The shipped indexer model stays explicit and narrow:

- every runtime report names the operator-visible service or event processor
- indexer lag is measured against canonical chain or checkpoint head, not
  against optimistic local assumptions
- `drifted` means the service is materially behind or inconsistent and should
  not be treated as authoritative
- `replaying` means the service is intentionally rebuilding state against a
  canonical head after a reorg or rollback

## Emergency Controls

The shipped emergency-control posture is bounded:

- `chio-link` can globally pause conversion or disable specific pairs or chains
- `chio-anchor` can enter `publish_paused`, `proof_import_only`,
  `recovery_only`, or `halted` modes
- `chio-settle` can enter `dispatch_paused`, `refund_only`, `recovery_only`,
  or `halted` modes
- on-chain contract pause gates new risk and operator-mediated movement while
  leaving expired escrow refunds and expired bond principal recovery open

These controls narrow write behavior only. They do not rewrite prior receipts,
proofs, or finality state. Qualification records the resulting control-state
snapshots and append-only control traces so operators can audit who changed
runtime posture, when, and from which incident or drill source.

## Generated Qualification Outputs

The primary live evidence is generated, not handwritten:

- local qualification writes artifacts under `target/web3-ops-qualification/`
- hosted release qualification stages the same family under
  `target/release-qualification/web3-runtime/ops/`
- operators should use the generated reports, control-state snapshots, and
  control traces for incident review; the checked-in example JSON files are
  schema references only

## Failure Posture

Web3 operations fail closed by default.

Operators must not keep normal publication or dispatch open when:

- indexers are `drifted` or `failed`
- canonical-chain drift marks a settlement or anchor event as `reorged`
- anchor publication requires replay against a canonical root-registry head
- settlement recovery requires refund-first or manual replay posture

## Non-Goals

This profile does not yet claim:

- autonomous incident remediation without explicit operator posture changes
- cross-region replicated indexers or consensus-backed ops state
- permissionless public dashboards or unauthenticated incident feeds
- silent continuation when canonical chain history and indexed history diverge
