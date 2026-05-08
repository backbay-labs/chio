# Bar 2 baseline -- four primitives protected by signed negative conformance

**Bar**: 2 (Lane B: wire the spec hot path).
**Baseline captured**: 2026-05-08.
**Baseline SHA**: `708c7bb33df43594f5e76542b05fca7a56d9689e`.
**Baseline branch**: `planning branch`.
**Authoritative source**: `crates/chio-conformance/tests/` directory listing + the four production call-site files cited per W3 corrections.

This file records the CURRENT (pre-release work) state of Bar 2 so the post-release work
delta is measurable against a fixed reference. Bar 2 close criteria are
normative in `.planning/trajectory-5/debate/00-SYNTHESIS.md` Lane B
(updated per R4 BLOCKER 1 to FOUR primitives) and `SHIP-BAR-TRACKER.md`
Bar 2 row.

---

## Per-primitive baseline matrix

The four Lane B primitives are: B1 (capability v2 single-entry verifier),
B2 (receipt v2 fail-closed under negotiated v2), B3 (anchor-batch
async-only with public witness), B4 (DSSE-conformant bilateral signing).
Each must close with: enforced production call site + spec MUST citation
+ signed negative conformance fixture that fails when wiring is removed.
Pre-release work, ZERO of four are protected by such a fixture.

### B1 -- Capability v2 single-entry verifier

| Field | Baseline value |
|---|---|
| Spec MUST citation | `spec/PROTOCOL.md` ~lines 408-418 (per Lane B README); CURRENTLY phrased as SHOULD; Lane B B1.4 promotes to MUST |
| Production call site (current bypass) | `crates/chio-kernel/src/kernel/mod.rs:4005-4033` (`verify_capability_full_without_budget_admit`) and `:4035-4058` (legacy `verify_capability_signature`) |
| Production call site (target) | All hosted callers route through `verify_capability_full`; bypass functions deleted |
| Existing conformance fixture file | NONE TODAY (verified by `ls crates/chio-conformance/tests/` -- no `b1_capability_v2_single_entry_no_bypass.rs`) |
| Expected post-release work fixture path | `crates/chio-conformance/tests/b1_capability_v2_single_entry_no_bypass.rs` |
| Current enforcement status | UNWIRED -- bypass functions callable from kernel hot path |

### B2 -- Receipt v2 fail-closed under negotiated v2

| Field | Baseline value |
|---|---|
| Spec MUST citation | `spec/PROTOCOL.md` lines 737-741 (per W3 BLOCKER #1 fix: prose currently has neither MUST nor SHOULD; Lane B B2.4 introduces a NEW normative MUST -- a tightening, not a promotion) |
| Production call site | `crates/chio-kernel/src/kernel/mod.rs:1574-1591` (`kernel_receipt_version_for_remote`) -- silently downgrades v2 -> v1 with a warning |
| Production call site (target) | `kernel_receipt_version_for_remote` hard-rejects v1 when negotiation indicated v2 |
| Existing conformance fixture file | NONE TODAY (verified by `ls crates/chio-conformance/tests/` -- a related file `verify_rejects_v2_token_when_peer_negotiated_v1_only.rs` exists but the B2 fixture `b2_receipt_v2_failclosed_under_negotiated_v2.rs` does not) |
| Expected post-release work fixture path | `crates/chio-conformance/tests/b2_receipt_v2_failclosed_under_negotiated_v2.rs` |
| Current enforcement status | PARTIALLY-ENFORCED -- warn-and-downgrade exists; fail-closed does not |

(Note: synthesis line 31 originally cited `:1148-1165` which is the
`KernelReceiptVersion::from_capabilities` resolver helper; the actual
runtime downgrade is at `:1574-1591`. W3 Lane B fix landed the
correction across all master/template/architecture/lane-b docs; pre-W3
references in legacy text are footnoted.)

### B3 -- Anchor-batch async-only with public witness

| Field | Baseline value |
|---|---|
| Spec MUST citation | `spec/PROTOCOL.md` §6.4.1 (arrow-notation rule promoted to MUST per W3 R3-MAJOR-7); also lines 982-991 |
| Production call site (current bypass) | `crates/chio-anchor/src/batch.rs:227-235` (sync wrapper still callable when `require_public_witness=true`) |
| Production call site (target) | sync wrapper hard-rejects `require_public_witness=true` at runtime; the runtime gate is the load-bearing defense (`scripts/check-anchor-batch-async-witness.sh` is best-effort fast-feedback, NOT the soundness guarantee per W3 BLOCKER #2 honest reframing) |
| Existing conformance fixture file | NONE TODAY -- there are anchor-batch fixtures in `crates/chio-conformance/tests/` (`anchor_batch_forged_root_rejected.rs`, `anchor_batch_misordered_proof_rejected.rs`, `anchor_batch_stale_replay_rejected.rs`, `anchor_batch_stale_witness_fallback.rs`, `anchor_batch_witness_impersonation_rejected.rs`) but the async-only-with-public-witness fixture is not among them |
| Expected post-release work fixture path | `crates/chio-conformance/tests/b3_anchor_batch_sync_path_rejected_under_public_witness.rs` |
| Current enforcement status | UNWIRED -- sync wrapper accepts `require_public_witness=true` today |

### B4 -- DSSE-conformant bilateral signing (NEW per R4 BLOCKER 1)

| Field | Baseline value |
|---|---|
| Spec MUST citation | `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 (DSSE PAE encoding) + §7 step 11-12 (signature verification) |
| Production call site (current legacy) | `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77): signs canonical-JSON bytes that share ZERO bytes with the §6 DSSE PAE preimage; `DualSignedReceipt::verify` (line 93+) is NOT a §6-conformant artifact |
| Production call site (target) | `crates/chio-federation/src/bilateral_dsse.rs` (NEW module per B4): produces a DSSE envelope whose Ed25519 signature is computed over DSSE PAE of the canonical-JSON in-toto Statement |
| Existing conformance fixture file | NONE TODAY (verified by `ls crates/chio-conformance/tests/` -- no `b4_bilateral_dsse_pae_only_is_conformant.rs`; no DSSE-related fixture exists) |
| Expected post-release work fixture path | `crates/chio-conformance/tests/b4_bilateral_dsse_pae_only_is_conformant.rs` |
| Current enforcement status | UNWIRED -- §6-conformant DSSE signing surface does not exist; `DualSignedReceipt::verify` accepts the legacy preimage |

(Pre-W3 framing: Lane C "Option A two-signature" adapter was proposed
but rejected as structural-without-wiring per R4-BLOCKER-1; the
DSSE-conformant signing primitive was promoted to Lane B sub-lane B4
during Wave 3.)

---

## Aggregate baseline summary

| Metric | Baseline (pre-release work) | Target (post-release work) |
|---|---|---|
| Primitives protected by signed negative conformance | 0 of 4 | 4 of 4 |
| Conformance fixtures in `crates/chio-conformance/tests/` matching the 4 expected names | 0 of 4 | 4 of 4 |
| `// negative-conformance: ...` annotations present | 0 of 4 | 4 of 4 |
| Production hot-path enforcement landed | 0 of 4 (B2 partial via warn) | 4 of 4 (fail-closed) |
| Spec MUST citations promoted/tightened | 0 of 4 | 4 of 4 |

## Evidence Gate close criteria each fixture must meet

Per `templates/EVIDENCE-GATE.md` (the four-artifact rule) each B<n>.E
close ticket lands four artifacts:

1. **Artifact A (production wiring)**: enforced production call site
   exists at the cited file:line; the bypass/legacy callable is
   deleted or migrated.
2. **Artifact B (spec MUST citation)**: PROTOCOL.md or
   CHIODOS_BILATERAL_COSIGN_INVOCATION.md normative line range reads
   MUST (B1, B3) or introduces NEW normative MUST (B2 tightening) or
   reads MUST against the DSSE PAE encoding (B4).
3. **Artifact C (signed negative conformance fixture)**: file exists at
   `crates/chio-conformance/tests/<b1-b4 fixture>.rs`; exercises the
   production call path; contains `// negative-conformance: removing
   X reintroduces Y` annotation; FAILS when the enforcement is
   removed (proven by inverting the patch under review).
4. **Artifact D (audit-doc evidence)**: `lane-b-wiring/<sub-lane>.md`
   carries a closing evidence section linking the file:line to the
   conformance test and to the spec line range.

The fifth row (banner update / Bar 2 status flip) is recorded in the
ship-bar tracker Bar 2 status cell when all four primitives close.

## Re-measurement protocol (release close)

For each of B1.E, B2.E, B3.E, B4.E the close-ticket Acceptance:

1. PR diff shows the production call site change.
2. PR diff shows the spec edit (MUST promotion or tightening).
3. PR diff shows the new conformance fixture file.
4. CI runs the conformance fixture and it PASSes.
5. Reverse-test PR (or local mutation) inverts the production
   enforcement; the fixture FAILs.
6. `scripts/check-trj5-ship-bar.sh` Bar-2 block PASSes:
   - 4 of 4 expected files exist;
   - each contains `// negative-conformance:` annotation;
   - the production call sites match the cited line ranges.

When all four close, the Bar 2 row in `SHIP-BAR-TRACKER.md` flips
NONE -> DONE.

## Pointers

- Lane B README: `.planning/trajectory-5/lane-b-wiring/README.md`
- Lane B PLAN: `.planning/trajectory-5/lane-b-wiring/PLAN.md`
- Lane B tickets: `.planning/trajectory-5/lane-b-wiring/planning docs`
- Sub-lane deep dives: `.planning/trajectory-5/lane-b-wiring/{async-trait-migration,single-entry-verifier,receipt-v2-failclosed,anchor-batch-async-only,dsse-bilateral-signing}.md`
- Conformance fixture pattern: `.planning/trajectory-5/lane-b-wiring/conformance-fixture-spec.md`
- Conformance fixture template: `.planning/trajectory-5/templates/CONFORMANCE-FIXTURE-PATTERN.md`
- Evidence Gate template: `.planning/trajectory-5/templates/EVIDENCE-GATE.md`
- Wave-2 sign-off: `.planning/trajectory-5/reviews/lane-b-wave2.md`
- Ship-bar tracker Bar 2 row: `.planning/trajectory-5/SHIP-BAR-TRACKER.md`

End of Bar 2 baseline.
