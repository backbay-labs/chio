# Research M09: Economic Layer And Lineage Pre-Flight

Date: 2026-04-30
Scope: M09 lineage plus economic primitives pre-flight research. This artifact
is planning guidance only. It does not implement tickets, amend protected
trajectory files, or open PRs.

## Inputs Read

- `.planning/trajectory-2/EXECUTION-STATE.json`
- `.planning/trajectory-2/EXECUTION-BOARD.md`
- `.planning/trajectory-2/AUTONOMOUS-PROMPT.md`
- `.planning/trajectory-2/09-economic-layer-and-lineage.md`
- `.planning/trajectory-2/tickets/manifest.yml`
- `.planning/trajectory-2/tickets/M09/README.md`
- `.planning/trajectory-2/tickets/M09/P0.yml` through `P5.yml`
- `.planning/trajectory-2/README.md`
- `.planning/trajectory-2/decisions.yml`
- `.planning/trajectory-2/OWNERS.toml`
- `CHANGELOG.md`
- `CLAUDE.md`
- `AGENTS.md`
- Receipt and evidence paths under `crates/chio-core-types`,
  `crates/chio-kernel`, `crates/chio-store-sqlite`, `crates/chio-anchor`,
  and `spec/PROTOCOL.md`
- Economic and governance paths under `crates/chio-credit`,
  `crates/chio-settle`, `crates/chio-link`, `crates/chio-market`,
  `crates/chio-underwriting`, `crates/chio-appraisal`,
  `crates/chio-reputation`, `crates/chio-governance`,
  `crates/chio-federation`, and `contracts/`

## Current Planning State

- M09 is Wave 4, non-trust-boundary, 38 tickets, 47.00 effort-days:
  `.planning/trajectory-2/tickets/M09/README.md:1-4`.
- `EXECUTION-STATE.json` currently has `current_wave: "W1"`, halt false,
  and M09 at `ticket files authored` / `ready_for_p0`:
  `.planning/trajectory-2/EXECUTION-STATE.json:5-67`.
- Wave assignment puts M09 and M10 in W4:
  `.planning/trajectory-2/EXECUTION-STATE.json:90-93`.
- The execution board says M09 wakes dormant economic crates and consumes M04
  delegation plus M06 CanonicalBytes:
  `.planning/trajectory-2/EXECUTION-BOARD.md:128-133`.
- M09 should precede M10 because lineage and economic activation unblock M10 P5
  anchoring:
  `.planning/trajectory-2/EXECUTION-BOARD.md:150-163`.
- Root `tickets/manifest.yml` does not exist in this checkout. The canonical
  generated manifest is `.planning/trajectory-2/tickets/manifest.yml`, whose
  header states it is generated from per-phase files:
  `.planning/trajectory-2/tickets/manifest.yml:1-7`.

## Locked Decisions

- D21 says M09 activates existing economic crates as-is and adds no new
  economic crates:
  `.planning/trajectory-2/decisions.yml:314-325`.
- D22 says `chio-lineage` is a SQLite-backed recursive-CTE indexer, not a graph
  database:
  `.planning/trajectory-2/decisions.yml:328-333`.
- D26 clarifies that `chio-mercury`, `chio-mercury-core`, and `chio-anchor`
  wake transitively, not through dedicated activation phases:
  `.planning/trajectory-2/decisions.yml:392-402`.
- The M09 README repeats the two direct locked decisions:
  `.planning/trajectory-2/tickets/M09/README.md:42-45`.

## Existing Receipt And Evidence Flow

M09 should treat the signed receipt as the single economic and lineage trigger.
The current runtime already establishes that boundary:

- `ChioReceipt` carries receipt id, timestamp, capability id, tool server,
  tool name, action, decision, content hash, policy hash, guard evidence,
  metadata, trust level, optional tenant id, kernel key, algorithm, and
  signature:
  `crates/chio-core-types/src/receipt.rs:92-144`.
- Receipt signing is over `ChioReceiptBody`; single-tenant receipts omit
  `tenant_id` from canonical JSON when absent:
  `crates/chio-core-types/src/receipt.rs:146-170`.
- Kernel receipt construction resolves tenant id from scoped authenticated
  context, not caller fields, and signs via the kernel-core boundary:
  `crates/chio-kernel/src/kernel/responses.rs:1262-1319`.
- Persistence happens after signing. `record_chio_receipt` appends to the
  receipt store, triggers checkpoints by sequence, and then appends to the
  local log:
  `crates/chio-kernel/src/kernel/responses.rs:1337-1351`.
- Checkpoint triggering is sequence and batch-size based:
  `crates/chio-kernel/src/kernel/responses.rs:1363-1369`.
- SQLite persists signed tool receipts in `chio_tool_receipts` with stable
  `seq`, unique `receipt_id`, capability, subject, issuer, decision, hashes,
  and raw JSON:
  `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs:32-60`.
- Kernel checkpoints sign a Merkle root over canonical receipt bytes and include
  checkpoint sequence, batch bounds, tree size, issued time, kernel key, and
  previous checkpoint hash:
  `crates/chio-kernel/src/checkpoint.rs:58-89` and
  `crates/chio-kernel/src/checkpoint.rs:775-803`.
- Evidence export bundles query, tool receipts, child receipts, checkpoints,
  capability lineage, inclusion proofs, uncheckpointed receipt markers, and
  retention metadata:
  `crates/chio-kernel/src/evidence_export.rs:207-220`.
- SQLite export assembly explicitly refuses to fabricate joins for child
  receipts, collects checkpoint coverage for exported tool receipts, and marks
  uncheckpointed receipts:
  `crates/chio-store-sqlite/src/evidence_export.rs:21-55` and
  `crates/chio-store-sqlite/src/evidence_export.rs:238-300`.

Pre-flight conclusion: IOU minting, settlement dispatch, marketplace accounting,
and lineage ingest must all attach after signed receipt finalization. None of
them should mutate receipt bytes or become a pre-signing requirement.

## Current Lineage Substrate

The repo already has enough lineage substrate to justify M09, but not the M09
graph surface.

- Capability lineage snapshots already store capability id, subject, issuer,
  issue/expiry times, grants JSON, depth, and parent capability id:
  `crates/chio-store-sqlite/src/capability_lineage.rs:31-83`.
- SQLite already has a recursive CTE for delegation chains with a depth guard:
  `crates/chio-store-sqlite/src/capability_lineage.rs:159-236`.
- Request lineage and receipt-lineage statement tables already exist:
  `crates/chio-store-sqlite/src/receipt_store/bootstrap.rs:642-696`.
- Protocol provenance classes are normative: `asserted`, `observed`, and
  `verified`:
  `spec/PROTOCOL.md:328-336`.
- The current bounded release emits session anchors and request-lineage records,
  while receipt-lineage statements and continuation tokens are stronger proof
  forms only when present:
  `spec/PROTOCOL.md:347-351`.
- Reports and exports must preserve the evidence class boundary instead of
  silently upgrading caller input:
  `spec/PROTOCOL.md:357-363`.
- Checkpoint proofs currently support audit and transparency-preview claims, not
  broad public append-only or strong non-repudiation claims:
  `spec/PROTOCOL.md:615-621`.

Gap: `crates/chio-lineage/` is absent. M09 must create it, but its first schema
should model existing ids and evidence classes instead of inventing new truth
levels. `lineage-graph.v1.json` should include prompt, capability, guard,
tool-call, receipt, request-lineage, receipt-lineage, checkpoint, and truncation
nodes while preserving `asserted` / `observed` / `verified`.

## Economic Primitive Snapshot

The economic layer is broad but mostly dormant from the runtime's point of view.
M09 should activate it by binding to receipts, not by redesigning it.

- `chio-credit` already defines exposure, scorecard, facility, bond,
  loss-lifecycle, provider-risk, capital-book, capital-instruction, allocation,
  and bonded-execution schemas:
  `crates/chio-credit/src/lib.rs:16-35`.
- `chio-credit` exposure entries already understand receipt ids, decision,
  settlement status, financial amount, reserve, provisional loss, recovery,
  metered flags, and evidence refs:
  `crates/chio-credit/src/lib.rs:129-216`.
- `chio-settle` is web3-gated and projects approved Chio capital instructions
  into contract calls and settlement receipts:
  `crates/chio-settle/src/lib.rs:1-18`.
- `chio-settle` already exposes EVM, CCIP, finality observation, ops controls,
  x402/Circle/EIP-3009/ERC-4337 payment helpers, and Solana settlement helpers:
  `crates/chio-settle/src/lib.rs:22-74`.
- `SettlementCommitment` is already receipt-referential and amount-bearing:
  `crates/chio-settle/src/lib.rs:76-99`.
- Settlement ops have emergency modes and operation-level allow rules:
  `crates/chio-settle/src/ops.rs:39-111`.
- `chio-link` is the FX/oracle authority. It produces fresh conversion
  evidence with source, feed address, cache age, original and converted cost:
  `crates/chio-link/src/lib.rs:42-150`.
- `chio-underwriting` already has risk classes, reason codes, evidence kinds,
  receipt evidence, reputation evidence, certification evidence, runtime
  assurance evidence, and compliance evidence:
  `crates/chio-underwriting/src/lib.rs:36-229`.
- `chio-reputation` is storage-agnostic local scoring from persisted receipts,
  capability-lineage records, and budget-usage records:
  `crates/chio-reputation/src/lib.rs:1-7`.
- `chio-market` already models liability providers, coverage classes, evidence
  requirements, provenance, and support boundaries:
  `crates/chio-market/src/lib.rs:33-144`.

Pre-flight conclusion: P1 should add the missing receipt-finalization IOU hook
and store binding only. P2 should add settlement hook behavior. P4 should use
`chio-appraisal` and `chio-underwriting` helpers without introducing new money,
bond, chain, or market primitives.

## Governance Touchpoints

M09 governance is not token voting. It is admission, freeze, sanction, appeal,
federated visibility, and operator controls.

- `chio-governance` defines generic governance charters and cases for dispute,
  freeze, sanction, and appeal:
  `crates/chio-governance/src/lib.rs:13-23`.
- Governance authority scope is namespace-bound and operator-scoped:
  `crates/chio-governance/src/lib.rs:78-101`.
- Governance cases require evidence refs and validate appeal/escalation shape:
  `crates/chio-governance/src/lib.rs:176-254`.
- `chio-federation` states that cross-operator visibility may flow, but runtime
  trust still requires explicit local activation and review:
  `crates/chio-federation/src/lib.rs:1-7`.
- Federation import controls default to explicit local activation, manual
  review, stale-input rejection, visibility without runtime trust, and no
  ambient runtime admission:
  `crates/chio-federation/src/lib.rs:138-158`.
- Federation open-admission policy can require a bond amount, slashability, and
  governance cases:
  `crates/chio-federation/src/lib.rs:245-255`.

M09 ignition should therefore thread governance through marketplace discovery
and publisher credential revocation, not through a new governance layer. The
runtime path remains local activation first.

## Web3 And Settlement Boundary

The economic layer can use web3 evidence, but web3 must not become canonical
truth.

- `chio-anchor` builds and verifies Chio checkpoint and receipt inclusion proof
  bundles from evidence exports:
  `crates/chio-anchor/src/lib.rs:149-200`.
- `chio-anchor` rejects evidence bundles where a requested receipt is
  uncheckpointed or missing/multiplied in the canonical bundle:
  `crates/chio-anchor/src/lib.rs:173-240`.
- Chainlink Functions fallback batches verify receipt signatures, canonical
  bodies, and Merkle leaves before request construction, and it explicitly
  rejects direct fund-release configuration:
  `crates/chio-anchor/src/functions.rs:141-226`.
- Contracts provide narrow identity, root publication, escrow, and bond-vault
  surfaces, but they are downstream settlement and anchor rails. They do not
  replace signed Chio receipts.

Pre-flight conclusion: M09 should keep `chio-link` as FX authority,
`chio-anchor` as proof/anchoring, and `chio-settle` as settlement execution.
External chains and payment interop remain bounded overlays.

## P0 Ignition Guidance

P0 is schedulable within M09 only after the Wave 4 gate opens. From the M09
ticket files, P0 has four pending tickets:

- M09.P0.T1 pins `petgraph` and `csv`, owns `Cargo.toml` and `Cargo.lock`, and
  must serialize lockfile changes:
  `.planning/trajectory-2/tickets/M09/P0.yml:16-34`.
- M09.P0.T2 creates `crates/chio-lineage/` and registers it in the workspace:
  `.planning/trajectory-2/tickets/M09/P0.yml:42-60`.
- M09.P0.T3 adds default-off `marketplace` and `lineage` feature flags:
  `.planning/trajectory-2/tickets/M09/P0.yml:68-85`.
- M09.P0.T4 opens the M09 audit doc with starting counts:
  `.planning/trajectory-2/tickets/M09/P0.yml:93-109`.

Recommended first PR shape when W4 opens:

1. Keep M09.P0.T1 alone if another ticket is already touching `Cargo.lock`.
2. If the lock lane is clear, combine P0.T1 and P0.T2 only. Do not include
   P0.T3 feature flags unless the branch can absorb the extra review safely.
3. Use root workspace dependency pins for `petgraph` and `csv`.
4. Keep `crates/chio-lineage/src/lib.rs` skeletal. Do not implement the DAG,
   ingest, diff, anchor pinning, or CLI in P0.
5. The audit doc should record live opening counts: no `crates/chio-lineage/`,
   no `CreditEvaluatorHook`, no `SettlementHook`, no `GuardPrice`, no
   `iou_envelope`, and no M09 recursive-CTE module.

P0 validation bundle:

```bash
cargo metadata --format-version 1 --no-deps --quiet > /dev/null
cargo build -p chio-lineage --quiet
cargo clippy -p chio-lineage -- -D warnings
cargo build -p chio-guard-registry --no-default-features --quiet
cargo build -p chio-guard-registry --features marketplace --quiet
cargo build -p chio-store-sqlite --features lineage --quiet
git diff --check
```

## P1 Ignition Guidance

P1 should not mix settlement work into credit activation. From the ticket files:

- M09.P1.T1 defines `CreditEvaluatorHook` for signed receipts to IOU envelopes:
  `.planning/trajectory-2/tickets/M09/P1.yml:10-30`.
- M09.P1.T2 implements in-memory IOU minting:
  `.planning/trajectory-2/tickets/M09/P1.yml:36-56`.
- M09.P1.T3 persists IOUs through an additive `iou_envelope` table:
  `.planning/trajectory-2/tickets/M09/P1.yml:62-82`.
- M09.P1.T4 and P1.T5 are the critical property and migration tests:
  `.planning/trajectory-2/tickets/M09/P1.yml:88-132`.

Implementation constraints for P1:

- Hook input is a finalized signed receipt plus price context. If signing fails,
  no IOU exists.
- Legacy receipts without manifest price produce zero IOUs and remain
  byte-identical.
- The SQLite migration is additive and idempotent. It must not rewrite
  `chio_tool_receipts.raw_json`.
- IOU minting must be idempotent by `receipt_id`, so replaying finalization does
  not double-mint.
- Settlement lifecycle belongs to P2. P1 can record enough state for later
  settlement but must not dispatch, retry, or dead-letter settlements.

P1 validation bundle:

```bash
cargo test -p chio-credit --quiet
cargo clippy -p chio-credit -- -D warnings
cargo test -p chio-store-sqlite --quiet
cargo test -p chio-credit --test iou_invariants
cargo test -p chio-credit --test legacy_receipt_migration
git diff --check
```

## P0/P1 Risk Ranking

P0 P0-risk-1: `Cargo.lock` collision. P0.T1 owns root `Cargo.toml` and
`Cargo.lock`, so it must obey the global lockfile serialization rule from
`.planning/trajectory-2/EXECUTION-BOARD.md:244-250`.

P0 P0-risk-2: overbuilding `chio-lineage`. P0.T2 is a skeleton ticket. Full
DAG schema starts at P5.T1.

P0 P0-risk-3: feature flag leakage. `marketplace` and `lineage` must be
default-off at P0.T3 so current guard registry and receipt store behavior remain
unchanged.

P1 P1-risk-1: IOU before signature. This would violate the signed-receipt
trigger. The hook must run after receipt finalization.

P1 P1-risk-2: non-idempotent replay. Reprocessing a receipt must not double
mint IOUs.

P1 P1-risk-3: legacy receipt mutation. Old receipts with no manifest price must
mint zero IOUs without changing receipt bytes.

P1 P1-risk-4: settlement bleed. P1 must not implement `SettlementHook`,
dead-letter tables, retries, or CLI settlement status. Those are P2.

P1 P1-risk-5: provenance-class flattening. `chio-lineage` and later IOU
evidence must preserve asserted/observed/verified boundaries.

## Likely P0/P1 Ignition Checklist

Before opening M09 P0:

- Confirm W4 gate is open and M04, M06, M07, and M08 dependencies are satisfied
  or explicitly marked soft/defensive by the board.
- Re-check current `petgraph` and `csv` versions on the day P0 opens, as the
  P0.T1 soft dependency requires:
  `.planning/trajectory-2/tickets/M09/P0.yml:28-31`.
- Check for live `Cargo.lock` owners and in-flight W4 worktrees.
- Confirm `crates/chio-lineage/` is still absent before scaffold work.
- Confirm no active freeze overlaps unexpectedly with `crates/chio-kernel/src/`
  or `crates/chio-store-sqlite/src/`.

Before opening M09 P1:

- Confirm P0.T4 audit baseline is merged.
- Confirm `CreditEvaluatorHook` is still absent so the P1 API can land cleanly.
- Decide the exact IOU envelope field set from existing `chio-credit`
  primitives before editing code.
- Select the idempotency key. Recommended: `receipt_id` plus guard package ref
  and tenant id when present, with `receipt_id` uniqueness as the hard stop.
- Keep settlement dispatch out of the branch.

## Bottom Line

M09 is feasible because the repo already has signed receipts, checkpointed
evidence bundles, capability/request lineage tables, dormant economic artifacts,
settlement rails, oracle evidence, reputation scoring, governance cases, and
federation admission controls. The milestone should not add a new economic
theory. It should activate existing primitives in this order:

1. Scaffold `chio-lineage` and feature gates.
2. Mint idempotent IOUs from finalized signed receipts.
3. Observe settlement after receipt finalization.
4. Feed reputation from arena and provider-equality evidence.
5. Price and install guards through the existing registry.
6. Index lineage as SQLite recursive CTEs with evidence-class preservation.
