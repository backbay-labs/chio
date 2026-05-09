# Trajectory 5 Closure Contract and Integration Map

Status: RW5 planning-boundary corrected; release integration still blocked.

This document is a historical integration map for release work. It is not a
release ledger and it is not proof that #620 contains the source/evidence
artifacts named below. R4 supersedes the previous merge-order language for
release purposes. The current planning ownership record and replacement
strategy live in `R4-MERGE-TOPOLOGY.md`.

The numbers below are taken from actual PR titles, source-branch review
records, baseline files, and the midpoint security audit at
`reviews/COMPREHENSIVE-CODE-SECURITY-AUDIT-2026-05-08.md`. Where a bar is
honestly partial or absent from #620, this document says so. The integrator
decides merge order; this document gives them the map.

RW5 correction: read the rows below as assurance and sequencing evidence, not
as product release claims. The current order is Lane B integration first, Lane A
evidence regenerated from the merged Lane B code second, Lane C canary after
Lane B, and #618 packaging last from merged `main`.

## Closure Contract

Trajectory 5 may close only as one of:

1. An accepted planning/integration map that gives reviewers a security-
   reviewable sequence.
2. An accepted assurance and claim matrix that names partial, blocked, and
   deferred rows honestly.

It may not close as release readiness, tag readiness, package readiness, or
evidence that future work has landed. Deferred work listed later in this file is
explicitly non-blocking future work outside current trajectory closure.

The old `docs/release/RELEASE_AUDIT.md` local-go posture is not inherited by
Trajectory 5. See `RELEASE-AUDIT-NON-INHERITANCE.md`.

## What source branches report

This trajectory prepared three coupled lanes on open PR branches. #620 carries
the planning and assurance matrix only. It does not vendor the source PR
artifacts listed in this section.

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
- Kani harnesses for chio-attest-verify (PR #605), chio-anchor and
  chio-weights (PR #613). This is PARTIAL release evidence:
  chio-attest-verify is DEFERRED-PARTIAL/MODEL-PARTIAL, and the three
  TEE harnesses (Nitro, SEV-SNP, TDX) are explicitly MODEL-ONLY.
- Multi-crate Kani CI manifest at `.kani/harnesses.toml` (PR #607)
  with empty-match-exit-1 enforcement (cleanup-wave fix to
  `scripts/run-kani-manifest.sh`) and a parity check between the
  legacy chio-kernel-core manifest and the new shared one.
- Bounded TLA+ rewrites (PR #602): `ReceiptBeforeAllow` split into
  `Allow = LogReceipt + PublishAllow`; `RevocationCutCompleteness`
  with bounded transitive-closure unrolling. This is PARTIAL release
  evidence, not implementation-complete production proof.
- Lean4 `negotiation_safety` (PR #601) re-proved against an executable
  model that mirrors the Rust verifier; replaces a `by rfl` tautology.
  This remains bounded formal evidence.

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
`ToolServerConnection`, PR #606) is containment/integration work, not durable
async kernel architecture closure. The sync bridge for the legacy evaluator
returns a typed `KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime`
when it detects a current-thread Tokio runtime (cleanup-wave response to audit
P0-002). Full sync-evaluator migration, cancellation/finalization coverage, and
durable async architecture remain later-phase work outside this closure
contract.

The section 7 bilateral verifier (`bilateral_verifier.rs`, PR #615) was
honestly downgraded from "partial local verifier subset" to "partial local
verifier" during the cleanup wave (audit P0-007); predicate schema
completion (`tool_args_hash`, `statement.malformed` mapping) is
tracked in `crates/chio-federation/NOTES.md`. Step 15 now defaults to
Reject for unknown tool names (was Routine fail-open; audit P0-006).

### Lane C (the demo)

The two-kernel cross-org bilateral cosigned invocation example at
`examples/chiodome-bilateral/` is source-branch evidence from PRs #614, #615,
and #617, not a runnable artifact in #620. It remains pending until those
branches merge after Lane B and the canary fixtures are regenerated from merged
`main`. The claimed source-branch target is deterministic seeded keypairs, a
real signed `ChioReceipt`, a DSSE envelope, and a `Web3CheckpointStatement`
whose merkle root uses RFC6962 leaf hashing.

`chio receipt --inspect-bilateral` (renamed from `--explain-bilateral`
after the audit caught the over-claim of cryptographic verification
in P0-008) renders the artifacts. The `chio-federation` `bbs-stub`
cargo feature (renamed from `bbs-stub` per audit P0-009) provides a
structured selective-disclosure placeholder that is explicitly labeled
NOT zero-knowledge; real BBS+ is future work outside current trajectory
closure. C5 selective disclosure is not a closure row. KB MCP integration (PR
#614) uses an `mcp-remote` stdio bridge against `:8111/mcp/`; the wrap path
produces mediation transcripts (not kernel-signed receipts) so C3 is honestly
labeled PARTIAL in the release map.

## Assurance Reconciliation

### Claim A -- mutation kill-rate floor + threat evidence: PARTIAL

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

Claim A closes only after the hosted-nightly authoritative run lands;
this trajectory delivered the measurement infrastructure, the floor
exists, and the gaps are honestly tagged.

### Claim B -- Lane B primitives protected by production-call-path conformance: PARTIAL/PENDING

Open source PR branches are expected to provide conformance fixtures under
`crates/chio-conformance/tests/`, each exercising the production call path.
These files are not present in #620:

- `b1_capability_v2_single_entry_no_bypass`
- `b2_receipt_v2_failclosed_pre_dispatch`
- `b3_anchor_batch_sync_path_rejected_under_public_witness`
- B4 is still pending full DSSE PAE conformance. The current upstream evidence
  found during R7 review is the interim `b4_bilateral_dsse_signature_slice`
  fixture, which explicitly does not claim full §6 predicate conformance.

Claim B remains PARTIAL/PENDING until those PRs merge, dependent branches
rebase, B4 full DSSE PAE conformance lands, fixtures are regenerated from
merged `main`, and checks are green on the integrated merge SHA.

### Claim C -- chiodome bilateral canary demo: PARTIAL

The demo runner and receipt rendering are branch-local evidence and are absent
from the #620 tree. They do not make Claim C assurance-complete until
#614/#615/#617/#618 merge, fixtures are regenerated from merged `main`, and
checks are green on the integrated merge SHA.

C3 (KB-MCP-mediated receipts) is PARTIAL: the wrap path produces
mediation transcripts, not kernel-signed receipts. The old release-bar
honesty wording is superseded by `SHIP-BAR-TRACKER.md`. Bounded package status
may live in root `releases.toml`
`[v0_1_0_bounded_chiodome].release_status` only after the release owner
regenerates it from merged `main` per the merge sequence below. PR #620 does
not author that root package truth.

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
  `releases.toml [v0_1_0_bounded_chiodome]` from merged `main`.
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

## Security-Reviewable Merge Strategy

The old recommended merge sequence and any 28-PR autonomous-train framing are
superseded. Do not use them as release trains or security review units.

Use `R4-MERGE-TOPOLOGY.md` as the current truth. The short form is:

1. #620 is the sole planning owner for `.planning/trajectory-5/**`.
2. Release-source integration starts with Lane B enforcement on a clean branch.
3. Lane A assurance evidence is regenerated from the merged Lane B code after
   branch ownership is clean.
4. #608 and #616 remain active, not superseded, until the threat owner
   collapses or rebases the threat series.
5. Lane C canary work starts only after Lane B source integration is real.
6. #618 release packaging remains last and must be regenerated from merged
   `main`.

## Non-Blocking Future Work Outside Closure

The following items are explicitly outside the current trajectory closure
contract. They do not have to be erased for Trajectory 5 to close as a planning
map or assurance matrix, and they must not be used as release readiness:

- Sync evaluator migration to fully-async path (legacy bridge becomes
  obsolete)
- Authoritative full-crate mutation runs on CI hosted-nightly
  `mutants.yml` without budget caps
- Real BBS+/BLS implementation replacing the `chio-federation`
  `bbs-stub` placeholder
- Predicate schema completion for the bilateral verifier
  (`tool_args_hash`, `statement.malformed` mapping, etc.)
- Distributed `ReceiptStore` and live `RevocationOracle` integrations
  for the §7 verifier
- Cross-host DSSE envelope emission via a DSSE-aware
  `BilateralCoSigningProtocol`
- Move `selective_disclosure` to a dedicated `chio-federation`
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
| #601 | A | PR branch | Re-prove negotiation_safety against an executable Rust model |
| #602 | A | PR branch | TLA+ rewrites: receipt-before-allow split and revocation-cut completeness |
| #603 | A | PR branch | Per-crate mutation baseline and .cargo/mutants.toml exclusion audit |
| #604 | A | PR branch | Threat-evidence backfill batch 1 (7 rows) |
| #605 | A | PR branch | Add Kani harnesses for chio-attest-verify |
| #606 | B | PR branch | BREAKING: async-trait migration of ToolServerConnection |
| #607 | A | PR branch | feat(release work/A3.5): Kani CI multi-crate manifest + workflow |
| #608 | A | PR branch | feat(release work/A2): backfill threat evidence (batch 2, 7 rows) |
| #609 | B | PR branch | feat(release work/B3): anchor-batch async-only when require_public_witness=true |
| #610 | B | PR branch | feat(release work/B4): DSSE-conformant bilateral signing per CHIODOS §6 |
| #611 | B | PR branch | feat(release work/B2): receipt v2 fail-closed under negotiated v2 |
| #612 | B | PR branch | feat(release work/b1): single-entry capability verifier |
| #613 | A | PR branch | feat(release work/a3): kani harnesses for chio-anchor and chio-weights |
| #614 | C | PR branch | feat(release work/C1+C3): chiodome bilateral demo scaffolding + KB MCP integration |
| #615 | C | PR branch | feat(release work/C2): bilateral cosigned invocation flow + partial §7 verifier subset |
| #616 | A | PR branch | feat(release work/A2): backfill threat evidence (batch 3, 6 rows; complete 20/20) |
| #617 | C | PR branch | feat(release work/C4+C5): receipt-explain bilateral + `chio-federation` `bbs-stub` placeholder |
| #618 | C | PR branch | feat(release work/C6): v0.1.0-bounded-chiodome release packaging |
| #619 | A | PR branch | feat(release work/A1): mutation baseline for chio-attest-verify (44.1% measured; target >=80%) |
| #620 | (planning) | planning branch | Trajectory 5 planning artifacts (lanes A/B/C, assurance matrix, kickoff prereqs) |
| #621 | A | PR branch | Mutation baseline for chio-guards (78.2% measured; target >=65%) |
| #622 | A | PR branch | Mutation baseline for chio-anchor (69.4% measured; target >=65%) |
| #623 | A | PR branch | Mutation baseline for chio-policy (80.2% measured; target >=65%; PARTIAL 314/418) |
| #624 | A | PR branch | Mutation baseline for chio-weights (68.3% measured; target >=65%) |
| #625 | A | PR branch | chio-attest-verify: close mutation gap with sigstore negative tests |
| #626 | A | PR branch | Mutation baseline for chio-kernel-core (73.6% measured; PARTIAL 62/343; target >=65%) |

## RW5 Issue Closure

| Issue | Closure in this document |
|---|---|
| RW5-BI-P0-001 | Closure is limited to accepted planning/integration map or assurance matrix. Future work is non-blocking. |
| RW5-BI-P0-002 | Replaces autonomous-train framing with Lane B, regenerated Lane A, Lane C canary, #618 last. |
| RW5-BI-P1-003 | C5 is not a closure row; it is future work outside current closure. |
| RW5-BI-P1-004 | Async migration is containment/integration only; durable async architecture is later work. |
| RW5-BI-P2-002 | RELEASE_AUDIT local-go posture is explicitly non-inherited. |
| RW5-BI-P2-003 | Legacy ship-bar names are not active release semantics. |

End of trajectory 5 closeout.
