# Trj5 Ship-Bar Tracker

This file is the per-bar ledger that release work grades against. The three bars are normative in `debate/00-SYNTHESIS.md` and are the externally-verifiable closing signal for the trajectory.

**R4+ release state (2026-05-08)**: 26 PRs open; integrator merge
pending. Bar statuses are reconciled in this file and in `CLOSEOUT.md`.
The aggregate close gate is described at the bottom of this file. The
release end-state is: Bar 1 PARTIAL (per-crate measurements landed but
full hosted-nightly re-baseline pending), Bar 2 PARTIAL (fixtures live
on open PR branches and must be regenerated/validated from merged
`main`), and Bar 3 PARTIAL (runner artifacts are branch-local, C3 emits
mediation transcripts by default, and release packaging must be
regenerated after merge). See `CLOSEOUT.md` for the reconciliation,
R4+ release-truth corrections, and recommended merge sequence.

**If any of the three slips, release work stays open.** No closeout erratum is needed because the bar is the kind a third party can verify.

The tracker is consumed by `scripts/check-bounded-ship-bar.sh` (companion to `scripts/bounded-release-preflight.sh`; both are required for release closeout). The script:

- asserts each bar's per-evidence machine-readable signal is present (per-crate mutation JSON for Bar 1, four conformance fixtures for Bar 2, demo dir + pinned receipt/envelope/checkpoint fixtures for Bar 3);
- emits one `OK` / `PARTIAL` / `FAIL` line per check and a final pass/fail summary;
- treats Bar 1 PARTIAL state honestly: a mutation JSON can print `OK` only when it carries a measured kill rate, `target_met:true`, an explicit full-scope result label, complete `evaluated == total_discovered` counts, and no partial/subset/interrupted/hand-picked scope markers. Any partial metadata prints `PARTIAL` (or `WARN` in `--diagnostic`) and fails the default release gate.

`scripts/bounded-release-preflight.sh` covers kickoff prerequisites (planning artifacts, OWNERS population, releases.toml block, Wave-2/3/4 review trail, drift cleanup); `scripts/check-bounded-ship-bar.sh` covers the three closing bars. The pattern matches the trj4 close-bar tracker at `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md`.

---

## Bar 1 -- Mutation banner and threat evidence (Lane A)

**Normative source**: `debate/00-SYNTHESIS.md` Lane A; "Ship bar (visible from outside)" item 1.

| Field | Value |
|---|---|
| **Current state** | NONE. Workspace banner reads 31%. `chio-attest-verify` is below the 80% target. All 20 `audits/evidence/threats/*.json` files have `caught: 0`, `needs_real_run: true`, `ran_at: "1970-01-01T00:00:00Z"`. The 20/0/0 PASS banner is a placeholder. (Note: synthesis says "21" threat-evidence files; on-disk count is 20, one per row in `spec/security/chio-threat-model.v1.json`. Lane A targets the on-disk count of 20 as authoritative; see `lane-a-floor/README.md` "Authoritative threat count" footnote.) |
| **Target state** | DONE. Workspace mutation banner reads `>=65%` (observed, not target). Per-crate breakdown attached. `chio-attest-verify` >= 80%. All 20 threat-evidence JSON files contain real `caught >= 1` data with non-1970 `ran_at`. The placeholder PASS is replaced with production-call-path evidence. (If Wave 1 triage flips one or more rows to `BLOCKED-BY-ARCHITECTURE` per Risk Register R3, the close bar narrows to "<n> of 20 covered, <m> deferred to trj6"; the README banner reflects the narrowed claim. The currently-expected deferral is 1: `wasm_guard_resource_exhaustion`.) |
| **Evidence required** | (1) `README.md` banner reflects observed kill rate, with per-crate table. (2) `audits/evidence/mutation/<crate>/<run-id>.json` populated for every trust-boundary crate, non-placeholder, with surviving-mutant list and explicit `# unreachable: <justification>` annotations. (3) `audits/evidence/threats/*.json` files: 20 of 20 with real `caught >= 1` and non-1970 `ran_at` (or "<n> of 20 covered, <m> deferred to trj6" if R3 fires). (4) `scripts/check-threat-coverage.sh` PASS at 20/0/0 with non-meta evidence. |
| **Validator** | Wave-2 reviewer + `scripts/check-bounded-ship-bar.sh` Bar-1 block. |
| **Machine-readable signal** | `audits/evidence/mutation/banner.json` (committed file with `{ "kill_rate": ">=65", "per_crate": [...], "observed": true, "ran_at": "<non-1970 RFC3339>" }`); `audits/evidence/threats/*.json` (20 files; each with `caught >= 1`, `ran_at != "1970-01-01T00:00:00Z"`, `needs_real_run: false`, and a `triage_status` field per Wave 1 triage). |
| **Trj4 wave absorbed** | TRJ4-010, TRJ4-011, TRJ4-012, TRJ4-013, TRJ4-014, TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018, TRJ4-019, TRJ4-040..049 |
| **Trj5 ticket(s)** | release work-A1, release work-A2, release work-A3, release work-A4, release work-A5 (Lean; renumbered from A6 per Wave 3), release work-A7 (and dependents per `lane-a-floor/planning docs`); each sub-lane closes under its `release work-A<n>.E` Evidence Gate ticket |
| **Status** | PARTIAL. Per-crate measurements landed via PRs #603, #619, #621, #622, #623, #624, #625, #626. Numbers: chio-credentials 74.1% PARTIAL; chio-attest-verify 44.1% baseline + 97.9% on touched lines via #625; chio-anchor 69.4% PARTIAL (214/262); chio-guards 78.2% PARTIAL-SUBSET (119/1291 on 8/27 files); chio-policy 80.2% PARTIAL (314/418); chio-weights 68.25% FULL; chio-kernel-core 73.58% PARTIAL (62/343). 20 of 20 threat-evidence rows backfilled (PRs #604, #608, #616) with two rows partial-sub-vector. CI hosted-nightly authoritative re-baseline pending. See `CLOSEOUT.md` for the full per-crate table and audit closure status. |

---

## Bar 2 -- Four Lane B primitives protected by signed negative conformance (Lane B)

**Normative source**: `debate/00-SYNTHESIS.md` Lane B; "Ship bar (visible from outside)" item 2. **Updated**: per R4 BLOCKER 1 / R3 review, B4 (DSSE-conformant bilateral signing) was promoted from Lane C "Option A two-signature" to a Lane B fourth primitive.

| Field | Value |
|---|---|
| **Current state** | NONE. `verify_capability_full_without_budget_admit` and legacy `verify_capability_signature` callable from `crates/chio-kernel/src/kernel/mod.rs:4005-4033` and `:4035-4058`, defeating the T1.0 capability-negotiation Evidence Gate. Receipt v2 silently downgrades to v1 with a warning at `chio-kernel/src/kernel/mod.rs:1574-1591` (`kernel_receipt_version_for_remote`) even when negotiation indicated `chio.capability.v2`. (The synthesis line 31 cited `:1148-1165`, which is the `KernelReceiptVersion::from_capabilities` resolver helper; the actual runtime downgrade is at `:1574-1591`.) Anchor-batch sync wrapper at `crates/chio-anchor/src/batch.rs:227-235` still callable when `require_public_witness=true` contradicts PROTOCOL.md sections 982-991. Bilateral cosign at `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share zero bytes with the §6 DSSE PAE preimage; `DualSignedReceipt::verify` (line 108) is NOT a §6-conformant artifact. |
| **Target state** | DONE. The FOUR primitives are each protected by a signed negative conformance fixture under `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed. Bypass call sites deleted; legacy callers migrated. PROTOCOL.md SHOULDs become MUSTs (B1); "falls back" line 737-741 becomes a new normative MUST (B2 tightening, not promotion); arrow-notation rule promoted to MUST (B3); §6-conformant DSSE Ed25519-over-PAE signing wired (B4). |
| **Evidence required** | (1) `crates/chio-kernel/src/kernel/mod.rs:4005-4033` and `:4035-4058` no longer route through bypass; `verify_capability_full_without_budget_admit` deleted; legacy `verify_capability_signature` callers migrated. PROTOCOL.md sections 408-418 read MUST. Signed negative test fails when bypass is reintroduced. (2) `chio-kernel/src/kernel/mod.rs:1574-1591` hard-rejects v1 when negotiation indicated v2. PROTOCOL.md section 6 lines 737-741 are rewritten to introduce a NEW normative MUST (this is a tightening, not a SHOULD->MUST promotion). Signed negative test fails when warn-and-downgrade is reintroduced. (3) `crates/chio-anchor/src/batch.rs:227-235` sync wrapper rejects `require_public_witness=true` at runtime; the runtime gate is the load-bearing defense, `scripts/check-anchor-batch-async-witness.sh` is best-effort fast-feedback only. Signed negative test fails when the runtime gate is removed. (4) `crates/chio-federation/src/bilateral_dsse.rs` (new module per B4) produces a DSSE envelope whose Ed25519 signature is computed over DSSE PAE of the canonical-JSON in-toto Statement per `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353. Signed negative test rejects an attempt to claim §6 conformance via the legacy `DualSignedReceipt`-only preimage. |
| **Validator** | Wave-2 reviewer + `scripts/check-bounded-ship-bar.sh` Bar-2 block. The script asserts that each conformance test exists, that inverting the patch under review causes the test to fail, and that the production call sites match the corrected line citations. |
| **Machine-readable signal** | Four files MUST exist under `crates/chio-conformance/tests/`: `b1_capability_v2_single_entry_no_bypass.rs`, `b2_receipt_v2_failclosed_under_negotiated_v2.rs`, `b3_anchor_batch_sync_path_rejected_under_public_witness.rs`, and `b4_bilateral_dsse_pae_only_is_conformant.rs`. Each MUST exercise the production call path and contain a `// negative-conformance: removing X reintroduces Y` annotation. `scripts/check-anchor-batch-async-witness.sh` MUST exist and exit 0 in CI as best-effort fast-feedback (NOT as the soundness guarantee). |
| **Trj4 wave absorbed** | TRJ4-100..104 + T1.0.E (capability v2); TRJ4-120..131 + T1.2.E (receipt v2); TRJ4-140..147 + T1.3.E (anchor-batch). B4 has no trj4 wave-plan absorption (R4 BLOCKER 1 is post-trj4 promotion). |
| **Trj5 ticket(s)** | release work-B0 (architectural prerequisite), release work-B1, release work-B2, release work-B3, release work-B4 (DSSE signing), release work-B1.E / B2.E / B3.E / B4.E (and dependents per `lane-b-wiring/planning docs`). |
| **Status** | PARTIAL. Four signed negative conformance fixtures are expected from open PR branches: `b1_capability_v2_single_entry_no_bypass.rs` (PR #612 on top of #606 B0 async-trait), `b2_receipt_v2_failclosed_under_negotiated_v2.rs` (PR #611), `b3_anchor_batch_sync_path_rejected_under_public_witness.rs` (PR #609), and `b4_bilateral_dsse_pae_only_is_conformant.rs` (PR #610). The release bar does not become DONE until those PRs merge, dependent branches rebase, fixtures are regenerated from merged `main`, and checks are green on the integrated merge SHA. |

---

## Bar 3 -- Bilateral demo end-to-end with `chio receipt explain` (Lane C)

**Normative source**: `debate/00-SYNTHESIS.md` Lane C; "Ship bar (visible from outside)" item 3.

| Field | Value |
|---|---|
| **Current state** | NONE. `crates/chio-federation/src/bilateral.rs` carries `CoSigningBody` and `DualSignedReceipt` substrates; `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA` exists; `crates/chio-anchor::Web3CheckpointStatement` exists; `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` and `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` are drafted. None are composed end-to-end as a runnable example; `chio receipt explain` does not yet inspect a real bilateral receipt. |
| **Target state** | DONE only after merge. The bounded bilateral demo runs end-to-end from merged `main`, the receipt is inspectable with `chio receipt explain`, the release fixtures are re-pinned under `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/`, `releases.toml` records the integrated merge SHA, checks are green, and a human pushes the `v0.1.0-bounded-chiodome` tag. |
| **Evidence required** | (1) `examples/chiodome-bilateral/` exists with the Cargo binary/example recipe used by PR #614 and the release notes. (2) The committed fixture set includes `receipt.json`, `envelope.json`, and `checkpoint.json` with regenerated hashes. (3) `chio receipt explain` runs against the captured receipt. (4) Capability lease + budget bond minted via `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA`; consumed at receipt-write. (5) Anchored through `crates/chio-anchor::Web3CheckpointStatement` (no live deployment). (6) C5 remains PARTIAL unless the `chio-federation` `bbs-stub` placeholder is replaced by real BBS+ wiring. (7) The default KB MCP smoke path may produce mediation transcripts, but kernel-signed Chio receipts require operator-provisioned full mode and are not the default release gate. (8) The release tag is recorded only after upstream merges, regeneration, green checks, and human tag push. |
| **Validator** | Wave-2 reviewer + `scripts/check-bounded-ship-bar.sh` Bar-3 block. The script asserts the example runs end-to-end on a fresh checkout, the golden file matches, and the release tag is recorded. |
| **Machine-readable signal** | `examples/chiodome-bilateral/` exists; the pinned fixture directory contains `receipt.json`, `envelope.json`, and `checkpoint.json`; `releases.toml` `[trajectory_5]` carries the planned release tag and later the integrated merge SHA; the release package is regenerated from merged `main` before a human tag push. |
| **Trj4 wave absorbed** | (none directly; Lane C is the additive forcing demo) |
| **Trj5 ticket(s)** | release work-C1, release work-C2, release work-C3, release work-C4, release work-C5, release work-C6 (and dependents per `lane-c-demo/planning docs`). |
| **Status** | PARTIAL. The runner pieces (PR #614 scaffolding + #615 partial local verifier subset + #617 receipt-explain/`chio-federation` `bbs-stub` placeholder) demonstrate bounded behavior on their own branches, but on this planning branch (#620) the `examples/chiodome-bilateral/` directory does not yet exist. `bash scripts/check-bounded-ship-bar.sh` Bar-3 artifact checks fail until #614/#615/#617/#618 merge to `main`, release fixtures are regenerated, and checks are green on the integrated merge SHA. C3 is PARTIAL because the default KB MCP wrap path produces mediation transcripts, not kernel-signed Chio receipts. |

---

## Aggregate close gate

```
Bar 1 status: PARTIAL -> target: DONE (CI hosted-nightly authoritative re-baseline pending)
Bar 2 status: PARTIAL -> target: DONE (fixtures regenerated and validated from merged main)
Bar 3 status: PARTIAL -> target: DONE (fixtures regenerated from merged main; C3 full receipt path remains deferred)

Trj5 closes when (Bar 1 == DONE) AND (Bar 2 == DONE) AND (Bar 3 == DONE).

R4+ state at close of the worker branches: all three bars remain
PARTIAL until upstream merges, release-package regeneration, green
checks on the integrated merge SHA, and human tag push. The remaining
gaps include CI hosted-nightly mutation re-baseline, KB-MCP
kernel-signed receipt emission as the default smoke path, full
predicate schema for the 17-step verifier, and real BBS+ wiring.
See `CLOSEOUT.md` for the integration map.
```

If any of the three slips, release work stays open.

The wave-summary pattern from trj4 applies here: each lane lands per-week summary docs under `lane-{a-floor,b-wiring,c-demo}/wave-summary-WK<n>.md` recording the per-bar deltas. Trj5 close-out drafts `TRAJECTORY-5-FINAL.md` only after all three bars read DONE in this tracker AND `scripts/check-bounded-ship-bar.sh` exits 0 against committed evidence.

## Status conventions

Each bar starts in `NONE` and transitions to `PARTIAL` (some evidence rows present but threshold unmet) and then `DONE`. The tracker refuses regressions: a row may not move from `DONE` -> `PARTIAL` or `PARTIAL` -> `NONE` without an explicit erratum entry. This protects against the trj4 pattern of structural framing without runtime wiring.
