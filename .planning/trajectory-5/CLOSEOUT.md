# Trajectory 5 closeout

Status: execution complete; 26 PRs open; integrator action required.

This document is the integration-coordination map for trj5. The numbers
below are taken from the actual PR titles, the post-cleanup-wave state
of `baselines/BAR-1-MUTATION.md`, and the midpoint security audit at
`reviews/COMPREHENSIVE-CODE-SECURITY-AUDIT-2026-05-08.md`. Where a bar
is honestly partial, this document says so. The integrator decides
merge order; this document gives them the map.

## What landed

This trajectory shipped three coupled lanes.

### Lane A (the floor)

- Mutation kill-rate baselines for all six trust-boundary crates plus
  chio-credentials. Per-crate measured numbers below; aggregate
  observed band is 44 to 80 percent depending on crate, with several
  rows honestly labeled PARTIAL because cargo-mutants ran under a
  budget cap or against a subset of the crate surface.
- 20-of-20 threat-evidence rows backfilled with real attack-call deny
  tests (PRs #604, #608, #616). Two rows (`pq_signature_downgrade`,
  `tool_server_escape`) are honestly marked partial because the
  deferred sub-vectors (hybrid-artifact downgrade, kernel sandbox
  escape) are scoped to a future trajectory.
- Real Kani harnesses for chio-attest-verify (PR #605), chio-anchor
  and chio-weights (PR #613). Three TEE harnesses (Nitro, SEV-SNP,
  TDX) are explicitly labeled MODEL-ONLY; runtime regression is
  covered by separate negative tests.
- Multi-crate Kani CI manifest at `.kani/harnesses.toml` (PR #607)
  with empty-match-exit-1 enforcement (cleanup-wave fix to
  `scripts/run-kani-manifest.sh`) and a parity check between the
  legacy chio-kernel-core manifest and the new shared one.
- TLA+ rewrites (PR #602): `ReceiptBeforeAllow` split into
  `Allow = LogReceipt + PublishAllow`; `RevocationCutCompleteness`
  with bounded transitive-closure unrolling. Both production specs
  verify at length=6; deliberately-broken variants fail at length=4.
- Lean4 `negotiation_safety` (PR #601) re-proved against an executable
  model that mirrors the Rust verifier; replaces a `by rfl`
  tautology.

### Lane B (the wiring)

Four hot-path primitives, each protected by a signed negative
conformance fixture under `crates/chio-conformance/tests/`:

- **B1 single-entry capability verifier** (PR #612):
  `verify_capability_full` is the only production path; legacy
  `verify_capability_full_without_budget_admit` deleted; legacy
  `verify_capability_signature` callers migrated. Spec edit lifts the
  entry to a normative MUST.
- **B2 receipt v2 fail-closed** (PR #611): when negotiation indicates
  v2 but the local producer would mint v1, the kernel returns
  `KernelError::ReceiptNegotiationDowngrade` BEFORE tool dispatch (the
  cleanup wave moved the check from post-dispatch to pre-dispatch in
  response to audit P0-001; a counting `ToolServerConnection`
  fixture proves the tool fn is not invoked under rejection).
- **B3 anchor-batch async-only when `require_public_witness=true`**
  (PR #609): sync route returns typed
  `AnchorError::SyncRouteRequiresAdvisoryPolicy`; an advisory grep
  gate `scripts/check-anchor-batch-async-witness.sh` flags obvious
  sync-call patterns; a conformance fixture proves enforcement at
  runtime.
- **B4 DSSE-conformant bilateral signing** (PR #610):
  `bilateral_dsse.rs` implements Ed25519 over DSSE PAE; subject
  digest binds the `ChioReceiptBody` (cleanup-wave fix to audit
  P0-004); multi-subject envelopes are rejected (audit P0-005);
  legacy `DualSignedReceipt` retained with non-§6-conformant
  disclaimer.

The architectural prerequisite (B0 async-trait migration of
`ToolServerConnection`, PR #606) landed across 47 impl sites in 31
files. The sync bridge for the legacy evaluator returns a typed
`KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime` when it
detects a current-thread Tokio runtime (cleanup-wave response to
audit P0-002); full sync-evaluator migration to async is deferred to
the next trajectory.

The 17-step bilateral verifier (`bilateral_verifier.rs`, PR #615) was
honestly downgraded from "17-step verifier" to "partial local
verifier" during the cleanup wave (audit P0-007); predicate schema
completion (`tool_args_hash`, `statement.malformed` mapping) is
tracked in `crates/chio-federation/NOTES.md`. Step 15 now defaults to
Reject for unknown tool names (was Routine fail-open; audit P0-006).

### Lane C (the demo)

A two-kernel cross-org bilateral cosigned invocation example at
`examples/chiodome-bilateral/` (PRs #614, #615, #617) runs end-to-end
with deterministic seeded keypairs (cleanup-wave fix to audit
P0-015); produces a real signed `ChioReceipt`, §6 DSSE envelope, and
a `Web3CheckpointStatement` whose merkle root uses RFC6962 leaf
hashing (cleanup-wave fix to audit P0-013).

`chio receipt --inspect-bilateral` (renamed from `--explain-bilateral`
after the audit caught the over-claim of cryptographic verification
in P0-008) renders the artifacts. The `bbs-stub` cargo feature
(renamed from `zk` per audit P0-009) provides a structured
selective-disclosure projection that is explicitly labeled NOT
zero-knowledge; real BBS+ is deferred. KB MCP integration (PR #614)
uses an `mcp-remote` stdio bridge against `:8111/mcp/`; the wrap path
produces mediation transcripts (not kernel-signed receipts) so C3 is
honestly labeled PARTIAL in the release.

## Ship-bar reconciliation

### Bar 1 -- mutation kill-rate floor + threat evidence: PARTIAL

Per-crate state (numbers from PR titles + `BAR-1-MUTATION.md` aggregate):

| Crate | Measured | Status | Notes |
|---|---|---|---|
| chio-credentials | 74.1% | PARTIAL | cargo-mutants does not cover 13 `include!()`d files; restructure to `mod` deferred (audit P0-022) |
| chio-attest-verify | 44.1% baseline | PARTIAL | gap-closure PR #625 adds 29 negative tests reaching 97.9% kill on the touched lines; full-crate rerun on CI hosted-nightly mutants.yml lane is the authoritative re-baseline (audit P1-001) |
| chio-anchor | 69.4% | PARTIAL | 214/262 mutants evaluated under 60-min cap (audit P0-021); meets >=65% on partial sample only |
| chio-guards | 78.2% | PARTIAL-SUBSET | 119/1291 mutants on a hand-picked 8-of-27-file subset (audit P0-019); crate-level target UNRESOLVED; `text_utils.rs` and `spider_sense.rs` excluded as advisory while flagged decision-capable (audit P0-020) |
| chio-policy | 80.2% | PARTIAL | 314/418 mutants evaluated |
| chio-weights | 68.25% | FULL | 66/66 mutants evaluated; only crate cleanly retiring its baseline this trajectory |
| chio-kernel-core | 73.58% | PARTIAL | 62/343 mutants evaluated; throughput throttled by parallel runs |

The CI hosted-nightly lane completes the partial runs without budget
caps and is the authoritative re-baseline. The per-crate breakdown
table replaces the placeholder `>=65%` banner that
`SHIP-BAR-TRACKER.md` originally targeted as the close signal.

Threat-evidence: 20 of 20 rows have real attack-call deny tests with
non-1970 `ran_at` and `caught >= 1`. Two rows (`pq_signature_downgrade`,
`tool_server_escape`) carry partial sub-vector closure as documented.

Bar 1 closes only after the hosted-nightly authoritative run lands;
this trajectory delivered the measurement infrastructure, the floor
exists, and the gaps are honestly tagged.

### Bar 2 -- four Lane B primitives protected by signed negative conformance: MET

Four signed negative conformance fixtures live under
`crates/chio-conformance/tests/`, each exercising the production call
path:

- `b1_capability_v2_single_entry_no_bypass`
- `b2_receipt_v2_failclosed_pre_dispatch` (cleanup-wave revision of
  the original post-dispatch fixture per audit P0-001)
- `b3_anchor_batch_sync_path_rejected_under_public_witness`
- `b4_bilateral_dsse_pae_only_is_conformant`

Each fixture contains a `// negative-conformance: ...` annotation per
the Bar 2 machine-readable signal in `SHIP-BAR-TRACKER.md`.

### Bar 3 -- chiodome bilateral demo end-to-end: MET for runner; PARTIAL for KB-MCP

The demo runner + receipt rendering are MET: `cargo run --example
chiodome-bilateral` produces all eight `audits/evidence/c-bilateral-smoke.json`
artifacts on a fresh checkout.

C3 (KB-MCP-mediated receipts) is PARTIAL: the wrap path produces
mediation transcripts, not kernel-signed receipts. The release-bar
honesty matrix lives in `releases.toml [trajectory_5]` and is the
authoritative status source after the integrator regenerates it from
merged `main` per the merge sequence below.

## Audit closure

The midpoint security audit
(`reviews/COMPREHENSIVE-CODE-SECURITY-AUDIT-2026-05-08.md`) raised
27 P0 and 9 P1 findings. The cleanup wave addressed 26 P0 + 3 P1.
The remaining items are integrator-only:

- **P0-024** (stacked PRs duplicate code): integrator rebases
  #614/#615/#617 onto #610 and #612 onto #606 during the merge
  sequence below.
- **P0-026** (release package #618 last): integrator merges #618
  last and regenerates fixtures, release notes, and
  `releases.toml [trajectory_5]` from merged `main`.
- **P0-007 partial** (predicate schema completion for the bilateral
  verifier): downgraded to "partial local verifier"; tracked in
  `crates/chio-federation/NOTES.md`; full schema completion deferred.
- **P1-001** (chio-attest-verify mutation coverage): #625 closes the
  gap on the touched lines; full-crate rerun on CI hosted-nightly is
  the authoritative re-baseline.
- **P1-002** (chio-credentials schema mutants time out): documented;
  deterministic negatives deferred.
- **P1-003** (chio-anchor skip directive): documented; underlying
  pre-existing test failure deferred.
- **P1-004** (TLA+ negative specs are local-only): documented;
  inverted CI wrapper deferred.

## Recommended merge sequence

1. **Planning bundle**: #620 (this branch).
2. **Foundational evidence** (no code overlap): #601, #602, #604.
3. **B0 async-trait foundation**: #606 first; rebase #612 to B1-only;
   merge #612.
4. **DSSE foundation**: #610; rebase #615, #617, #614 to remove
   vendored DSSE; merge #615; #617; #614 (mutual order ok within
   this group).
5. **Other Lane B and Lane A**: #609 (B3); #605 + #607 + #613 (Kani
   trio); #611 (B2); #608 + #616 (threat batches 2+3).
6. **Mutation evidence**: #603 first (sets aggregate-state header
   per audit P0-025), then #619, #621, #622, #623, #624, #625, #626
   in any order; final merge resolves the coordinated aggregate
   block trivially.
7. **Release packaging**: #618 last; regenerate fixtures, release
   notes, ship-bar status, and `releases.toml [trajectory_5]` from
   merged `main`; only then push the `v0.1.0-bounded-chiodome` tag.

## Deferred to subsequent trajectory

- Sync evaluator migration to fully-async path (legacy bridge becomes
  obsolete)
- Authoritative full-crate mutation runs on CI hosted-nightly
  `mutants.yml` without budget caps
- Real BBS+/BLS implementation behind a properly-named `zk` feature
- Predicate schema completion for the bilateral verifier
  (`tool_args_hash`, `statement.malformed` mapping, etc.)
- Distributed `ReceiptStore` and live `RevocationOracle` integrations
  for the §7 verifier
- Cross-host DSSE envelope emission via a DSSE-aware
  `BilateralCoSigningProtocol`
- Move `selective_disclosure` to a dedicated `chio-zk-receipts`
  crate
- Restructure chio-credentials `include!()` to `mod` for full
  mutation coverage
- Workspace-scope mutation rerun on chio-attest-verify after fixing
  the chio-acp-proxy pre-existing test failure
- chio-guards full mutation surface (re-included `text_utils.rs` and
  `spider_sense.rs`)
- Hybrid PQ wire-format SIGNING dispatch + the deferred half of
  `pq_signature_downgrade` and `tool_server_escape` threats

## PR index

| PR | Lane | Branch | Title |
|---|---|---|---|
| #601 | A | claude/trj5/a5-lean-negotiation-safety | Re-prove negotiation_safety against an executable Rust model |
| #602 | A | claude/trj5/a4-tla-rewrites | TLA+ rewrites: receipt-before-allow split and revocation-cut completeness |
| #603 | A | claude/trj5/a1-mutation-baseline | Per-crate mutation baseline and .cargo/mutants.toml exclusion audit |
| #604 | A | claude/trj5/a2-threat-evidence-batch1 | Threat-evidence backfill batch 1 (7 rows) |
| #605 | A | claude/trj5/a3-kani-attest-verify | Add Kani harnesses for chio-attest-verify |
| #606 | B | claude/trj5/b0-async-trait-migration | BREAKING: async-trait migration of ToolServerConnection |
| #607 | A | claude/trj5/a3.5-kani-ci-multi-crate | feat(trj5/A3.5): Kani CI multi-crate manifest + workflow |
| #608 | A | claude/trj5/a2-threat-evidence-batch2 | feat(trj5/A2): backfill threat evidence (batch 2, 7 rows) |
| #609 | B | claude/trj5/b3-anchor-batch-async-only | feat(trj5/B3): anchor-batch async-only when require_public_witness=true |
| #610 | B | claude/trj5/b4-dsse-bilateral-signing | feat(trj5/B4): DSSE-conformant bilateral signing per CHIODOS §6 |
| #611 | B | claude/trj5/b2-receipt-v2-failclosed | feat(trj5/B2): receipt v2 fail-closed under negotiated v2 |
| #612 | B | claude/trj5/b1-single-entry-verifier | feat(trj5/b1): single-entry capability verifier |
| #613 | A | claude/trj5/a3-kani-anchor-weights | feat(trj5/a3): kani harnesses for chio-anchor and chio-weights |
| #614 | C | claude/trj5/c1-c3-demo-scaffolding-kb-mcp | feat(trj5/C1+C3): chiodome bilateral demo scaffolding + KB MCP integration |
| #615 | C | claude/trj5/c2-bilateral-cosign-flow | feat(trj5/C2): bilateral cosigned invocation flow + §7 17-step verifier |
| #616 | A | claude/trj5/a2-threat-evidence-batch3 | feat(trj5/A2): backfill threat evidence (batch 3, 6 rows; complete 20/20) |
| #617 | C | claude/trj5/c4-c5-receipt-explain-and-zk | feat(trj5/C4+C5): receipt-explain bilateral + selective-disclosure zk feature |
| #618 | C | claude/trj5/c6-release-packaging | feat(trj5/C6): v0.1.0-bounded-chiodome release packaging |
| #619 | A | claude/trj5/a1-mutation-attest-verify | feat(trj5/A1): mutation baseline for chio-attest-verify (44.1% measured; target >=80%) |
| #620 | (planning) | claude/charming-feistel-8595da | Trajectory 5 planning artifacts (lanes A/B/C, ship-bar, kickoff prereqs) |
| #621 | A | claude/trj5/a1-mutation-guards | Mutation baseline for chio-guards (78.2% measured; target >=65%) |
| #622 | A | claude/trj5/a1-mutation-anchor | Mutation baseline for chio-anchor (69.4% measured; target >=65%) |
| #623 | A | claude/trj5/a1-mutation-policy | Mutation baseline for chio-policy (80.2% measured; target >=65%; PARTIAL 314/418) |
| #624 | A | claude/trj5/a1-mutation-weights | Mutation baseline for chio-weights (68.3% measured; target >=65%) |
| #625 | A | claude/trj5/a1-attest-verify-gap-closure | chio-attest-verify: close mutation gap with sigstore negative tests |
| #626 | A | claude/trj5/a1-mutation-kernel-core | Mutation baseline for chio-kernel-core (73.6% measured; PARTIAL 62/343; target >=65%) |

End of trajectory 5 closeout.
