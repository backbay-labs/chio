# Trj5 Ship-Bar Tracker

This file is the per-bar ledger that trj5 grades against. The three bars are normative in `debate/00-SYNTHESIS.md` and are the externally-verifiable closing signal for the trajectory.

**If any of the three slips, trj5 stays open.** No closeout erratum is needed because the bar is the kind a third party can verify.

The tracker is consumed by `scripts/check-trj5-ship-bar.sh` (lands as a Wave 0 deliverable). The script:

- asserts each bar's machine-readable signal is present and meets threshold;
- emits `audits/evidence/trj5-ship-bar.json` for downstream tooling;
- refuses regressions (DONE -> PARTIAL or PARTIAL -> NONE).

The pattern matches the trj4 close-bar tracker at `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md`.

---

## Bar 1 -- Mutation banner and threat evidence (Lane A)

**Normative source**: `debate/00-SYNTHESIS.md` Lane A; "Ship bar (visible from outside)" item 1.

| Field | Value |
|---|---|
| **Current state** | NONE. Workspace banner reads 31%. `chio-attest-verify` is below the 80% target. All 20 `audits/evidence/threats/*.json` files have `caught: 0`, `needs_real_run: true`, `ran_at: "1970-01-01T00:00:00Z"`. The 20/0/0 PASS banner is a placeholder. (Note: synthesis says "21" threat-evidence files; on-disk count is 20, one per row in `spec/security/chio-threat-model.v1.json`. Lane A targets the on-disk count of 20 as authoritative; see `lane-a-floor/README.md` "Authoritative threat count" footnote.) |
| **Target state** | DONE. Workspace mutation banner reads `>=65%` (observed, not target). Per-crate breakdown attached. `chio-attest-verify` >= 80%. All 20 threat-evidence JSON files contain real `caught >= 1` data with non-1970 `ran_at`. The placeholder PASS is replaced with production-call-path evidence. (If Wave 1 triage flips one or more rows to `BLOCKED-BY-ARCHITECTURE` per Risk Register R3, the close bar narrows to "<n> of 20 covered, <m> deferred to trj6"; the README banner reflects the narrowed claim. The currently-expected deferral is 1: `wasm_guard_resource_exhaustion`.) |
| **Evidence required** | (1) `README.md` banner reflects observed kill rate, with per-crate table. (2) `audits/evidence/mutation/<crate>/<run-id>.json` populated for every trust-boundary crate, non-placeholder, with surviving-mutant list and explicit `# unreachable: <justification>` annotations. (3) `audits/evidence/threats/*.json` files: 20 of 20 with real `caught >= 1` and non-1970 `ran_at` (or "<n> of 20 covered, <m> deferred to trj6" if R3 fires). (4) `scripts/check-threat-coverage.sh` PASS at 20/0/0 with non-meta evidence. |
| **Validator** | Wave-2 reviewer + `scripts/check-trj5-ship-bar.sh` Bar-1 block. |
| **Machine-readable signal** | `audits/evidence/mutation/banner.json` (committed file with `{ "kill_rate": ">=65", "per_crate": [...], "observed": true, "ran_at": "<non-1970 RFC3339>" }`); `audits/evidence/threats/*.json` (20 files; each with `caught >= 1`, `ran_at != "1970-01-01T00:00:00Z"`, `needs_real_run: false`, and a `triage_status` field per Wave 1 triage). |
| **Trj4 wave absorbed** | TRJ4-010, TRJ4-011, TRJ4-012, TRJ4-013, TRJ4-014, TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018, TRJ4-019, TRJ4-040..049 |
| **Trj5 ticket(s)** | TRJ5-A1, TRJ5-A2, TRJ5-A3, TRJ5-A4, TRJ5-A5 (Lean; renumbered from A6 per Wave 3), TRJ5-A7 (and dependents per `lane-a-floor/tickets.md`); each sub-lane closes under its `TRJ5-A<n>.E` Evidence Gate ticket |
| **Status** | NONE |

---

## Bar 2 -- Four Lane B primitives protected by signed negative conformance (Lane B)

**Normative source**: `debate/00-SYNTHESIS.md` Lane B; "Ship bar (visible from outside)" item 2. **Updated**: per R4 BLOCKER 1 / R3 review, B4 (DSSE-conformant bilateral signing) was promoted from Lane C "Option A two-signature" to a Lane B fourth primitive.

| Field | Value |
|---|---|
| **Current state** | NONE. `verify_capability_full_without_budget_admit` and legacy `verify_capability_signature` callable from `crates/chio-kernel/src/kernel/mod.rs:4005-4033` and `:4035-4058`, defeating the T1.0 capability-negotiation Evidence Gate. Receipt v2 silently downgrades to v1 with a warning at `chio-kernel/src/kernel/mod.rs:1574-1591` (`kernel_receipt_version_for_remote`) even when negotiation indicated `chio.capability.v2`. (The synthesis line 31 cited `:1148-1165`, which is the `KernelReceiptVersion::from_capabilities` resolver helper; the actual runtime downgrade is at `:1574-1591`.) Anchor-batch sync wrapper at `crates/chio-anchor/src/batch.rs:227-235` still callable when `require_public_witness=true` contradicts PROTOCOL.md sections 982-991. Bilateral cosign at `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share zero bytes with the §6 DSSE PAE preimage; `DualSignedReceipt::verify` (line 108) is NOT a §6-conformant artifact. |
| **Target state** | DONE. The FOUR primitives are each protected by a signed negative conformance fixture under `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed. Bypass call sites deleted; legacy callers migrated. PROTOCOL.md SHOULDs become MUSTs (B1); "falls back" line 737-741 becomes a new normative MUST (B2 tightening, not promotion); arrow-notation rule promoted to MUST (B3); §6-conformant DSSE Ed25519-over-PAE signing wired (B4). |
| **Evidence required** | (1) `crates/chio-kernel/src/kernel/mod.rs:4005-4033` and `:4035-4058` no longer route through bypass; `verify_capability_full_without_budget_admit` deleted; legacy `verify_capability_signature` callers migrated. PROTOCOL.md sections 408-418 read MUST. Signed negative test fails when bypass is reintroduced. (2) `chio-kernel/src/kernel/mod.rs:1574-1591` hard-rejects v1 when negotiation indicated v2. PROTOCOL.md section 6 lines 737-741 are rewritten to introduce a NEW normative MUST (this is a tightening, not a SHOULD->MUST promotion). Signed negative test fails when warn-and-downgrade is reintroduced. (3) `crates/chio-anchor/src/batch.rs:227-235` sync wrapper rejects `require_public_witness=true` at runtime; the runtime gate is the load-bearing defense, `scripts/check-anchor-batch-async-witness.sh` is best-effort fast-feedback only. Signed negative test fails when the runtime gate is removed. (4) `crates/chio-federation/src/bilateral_dsse.rs` (new module per B4) produces a DSSE envelope whose Ed25519 signature is computed over DSSE PAE of the canonical-JSON in-toto Statement per `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353. Signed negative test rejects an attempt to claim §6 conformance via the legacy `DualSignedReceipt`-only preimage. |
| **Validator** | Wave-2 reviewer + `scripts/check-trj5-ship-bar.sh` Bar-2 block. The script asserts that each conformance test exists, that inverting the patch under review causes the test to fail, and that the production call sites match the corrected line citations. |
| **Machine-readable signal** | Four files MUST exist under `crates/chio-conformance/tests/`: `single_entry_verifier_no_bypass.rs`, `receipt_v2_fail_closed_under_negotiated_v2.rs`, `anchor_batch_async_only_with_public_witness.rs`, and `bilateral_dsse_pae_only_is_conformant.rs` (B4). Each MUST exercise the production call path and contain a `// negative-conformance: removing X reintroduces Y` annotation. `scripts/check-anchor-batch-async-witness.sh` MUST exist and exit 0 in CI as best-effort fast-feedback (NOT as the soundness guarantee). |
| **Trj4 wave absorbed** | TRJ4-100..104 + T1.0.E (capability v2); TRJ4-120..131 + T1.2.E (receipt v2); TRJ4-140..147 + T1.3.E (anchor-batch). B4 has no trj4 wave-plan absorption (R4 BLOCKER 1 is post-trj4 promotion). |
| **Trj5 ticket(s)** | TRJ5-B0 (architectural prerequisite), TRJ5-B1, TRJ5-B2, TRJ5-B3, TRJ5-B4 (DSSE signing), TRJ5-B1.E / B2.E / B3.E / B4.E (and dependents per `lane-b-wiring/tickets.md`). |
| **Status** | NONE |

---

## Bar 3 -- Bilateral demo end-to-end with `chio receipt explain` (Lane C)

**Normative source**: `debate/00-SYNTHESIS.md` Lane C; "Ship bar (visible from outside)" item 3.

| Field | Value |
|---|---|
| **Current state** | NONE. `crates/chio-federation/src/bilateral.rs` carries `CoSigningBody` and `DualSignedReceipt` substrates; `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA` exists; `crates/chio-anchor::Web3CheckpointStatement` exists; `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` and `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` are drafted. None are composed end-to-end as a runnable example; `chio receipt explain` does not yet inspect a real bilateral receipt. |
| **Target state** | DONE. The two-kernel cross-org bilateral cosigned invocation runs end-to-end. The receipts are inspectable with `chio receipt explain`. The demo run is captured as a fixture under `examples/bounded-chiodome/`. Honest release tag `v0.1.0-bounded-chiodome` cut under v3.18 bounded-claim discipline. |
| **Evidence required** | (1) `examples/bounded-chiodome/` exists with a `Makefile` or `cargo run --example` recipe that runs the demo end-to-end on a fresh checkout. (2) Two-kernel transcripts committed under `examples/bounded-chiodome/transcripts/`. (3) `chio receipt explain` golden output committed under `examples/bounded-chiodome/golden/<receipt-body-hash>.txt`. (4) Capability lease + budget bond minted via `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA`; consumed at receipt-write. (5) Anchored through `crates/chio-anchor::Web3CheckpointStatement` (no live deployment). (6) Selective-disclosure auditor view runs behind `zk` Cargo feature flag. (7) Wrapped at `chio mcp serve --policy` against `ops/knowledge-base/`. (8) Honest release tag `v0.1.0-bounded-chiodome` recorded in `releases.toml` `[trajectory_5]`. |
| **Validator** | Wave-2 reviewer + `scripts/check-trj5-ship-bar.sh` Bar-3 block. The script asserts the example runs end-to-end on a fresh checkout, the golden file matches, and the release tag is recorded. |
| **Machine-readable signal** | `examples/bounded-chiodome/Makefile` (or `Cargo.toml` example entry) exists; `examples/bounded-chiodome/transcripts/*.json` non-empty; `examples/bounded-chiodome/golden/*.txt` matches `chio receipt explain` output for the captured receipt; `releases.toml` `[trajectory_5]` carries `v0_1_0_bounded_chiodome_release_tag = "v0.1.0-bounded-chiodome"`. |
| **Trj4 wave absorbed** | (none directly; Lane C is the additive forcing demo) |
| **Trj5 ticket(s)** | TRJ5-C1, TRJ5-C2, TRJ5-C3, TRJ5-C4, TRJ5-C5, TRJ5-C6 (and dependents per `lane-c-demo/tickets.md`). |
| **Status** | NONE |

---

## Aggregate close gate

```
Bar 1 status: NONE  -> target: DONE
Bar 2 status: NONE  -> target: DONE
Bar 3 status: NONE  -> target: DONE

Trj5 closes when (Bar 1 == DONE) AND (Bar 2 == DONE) AND (Bar 3 == DONE).
```

If any of the three slips, trj5 stays open.

The wave-summary pattern from trj4 applies here: each lane lands per-week summary docs under `lane-{a-floor,b-wiring,c-demo}/wave-summary-WK<n>.md` recording the per-bar deltas. Trj5 close-out drafts `TRAJECTORY-5-FINAL.md` only after all three bars read DONE in this tracker AND `scripts/check-trj5-ship-bar.sh` exits 0 against committed evidence.

## Status conventions

Each bar starts in `NONE` and transitions to `PARTIAL` (some evidence rows present but threshold unmet) and then `DONE`. The tracker refuses regressions: a row may not move from `DONE` -> `PARTIAL` or `PARTIAL` -> `NONE` without an explicit erratum entry. This protects against the trj4 pattern of structural framing without runtime wiring.
