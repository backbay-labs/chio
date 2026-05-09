# W3 Lane B Fix-log

**Wave 3 Lane B fix agent**, 2026-05-07.

This document is the fix-log for Wave 3 Lane B remediation, addressing R3 (Lane B compliance review), the cross-cutting drift findings of R1, and R4 BLOCKER 1 (DSSE Option-A insufficiency, promoted to a new B4 sub-lane).

---

## R3 findings addressed

### R3 BLOCKER #1: B2 spec-language framing (PROTOCOL.md §737-741)

**Severity**: BLOCKER. **Status**: FIXED.

**Summary of fix**: Reframed B2's spec edit as introducing a NEW normative MUST (a tightening) rather than promoting an existing SHOULD. Lines 737-741 today contain neither MUST nor SHOULD; the prose is descriptive ("the kernel falls back"). The audit-doc evidence section MUST mark the change as "tightening" not "promotion" so the reviewer does not misread it.

**Files patched**:
- `lane-b-wiring/receipt-v2-failclosed.md`: added explicit "Spec-language framing (R3 BLOCKER #1 fix)" paragraph; clarified Case E covers both "stale" and "never-pinned"; updated "Why this design satisfies the Evidence Gate" to explicitly call out tightening vs promotion.
- `lane-b-wiring/PLAN.md`: rewrote B2 "Spec citation" to call out the descriptive-prose-with-no-modal-verb starting state and frame the change as introducing a NEW normative MUST. Updated acceptance criterion 4 to say "tightening, not promotion".
- `lane-b-wiring/planning docs`: rewrote release work-B2.4 ticket title and description to say "introduces NEW normative MUST" with explicit tightening framing.
- `templates/EVIDENCE-GATE.md`: §1.2 (Artifact B) extended to explicitly recognize TWO valid paths (promotion AND tightening); the script reads from merged-branch HEAD so a same-PR spec edit satisfies the gate.

### R3 BLOCKER #2: B3 lint script soundness contract

**Severity**: BLOCKER. **Status**: FIXED (Option A: honest reframing, NOT AST upgrade).

**Summary of fix**: The 50-line-window grep heuristic CANNOT guarantee zero false-negatives. Per R3 finding #5, chose Option A (honest reframing): the runtime gate at `batch.rs:227-235` is the load-bearing defense; the lint is best-effort fast-feedback documentation. Both false-positives AND false-negatives are now tolerated. AST upgrade is OUT OF SCOPE for release work (deferred to trj6).

**Files patched**:
- `lane-b-wiring/anchor-batch-async-only.md`: rewrote "The script's contract" section to explicitly enumerate the false-negative scenarios (cross-function policy construction, JSON-deserialized policies, builder-pattern construction, cross-crate calls) and reframe the lint as fast-feedback only. Updated "Why this design satisfies the Evidence Gate" footer.
- `lane-b-wiring/PLAN.md`: B3 acceptance criterion 2 reframed honestly.
- `lane-b-wiring/planning docs`: release work-B3.3 effort reduced from M to S (since the lint is no longer claiming soundness, scope is smaller); ticket text records the reframed contract.

### R3 BLOCKER #3: B0 impl count audit (47 sites in 31 files, not 31 impls)

**Severity**: BLOCKER. **Status**: FIXED.

**Summary of fix**: Per R3 finding #6, the prior 31 number counts FILES with at least one impl. The actual impl-site count is 47. Several files contain multiple impls; the catalogue is now corrected.

**Files patched**:
- `lane-b-wiring/async-trait-migration.md`: "Blast-radius numbers" section updated to reconcile 31 (files) vs 47 (sites); added enumeration of files with multiple impls.
- `lane-b-wiring/planning docs`: release work-B0.1 ticket updated to require BOTH file-count and site-count verification.
- `architecture/ASYNC-KERNEL-MIGRATION.md`: §1.3 inventory table shows both site-count (47) and file-count (31), plus the corrected `&mut self` count (24 method definitions, 36 occurrences). §5 diff size table notes the impl-site count.

### R3 MAJORs addressed

- **#3 (single-entry-verifier error mapping)**: release work-B1.2 ticket extended to require typed deny reasons (`InvalidSignature`, `AttenuationViolation`, `SchemaExceedsNegotiatedCeiling`) at all four hosted call sites, not just generic `KernelError::InvalidSignature`.
- **#1 reservation (B2 helper functions)**: `lane-b-wiring/receipt-v2-failclosed.md` updated to specify that `count_v1_receipts` and `count_v2_receipts` MUST read from the real SQLite tables directly, not via a kernel-side `test_only_*` accessor (avoiding the `EVIDENCE-GATE.md` §8.3 anti-pattern).
- **#4 last paragraph (B2 stale vs never-pinned)**: spec edit now explicitly enumerates both "stale" and "never-pinned" cases so a future implementation cannot misread "not pinned fresh" as "stale only".
- **#7 spec MUST citations (B3 promotion of arrow notation)**: PLAN.md retains B3.4 spec edit; Wave-1 audit-doc owner is responsible for noting the arrow notation is being upgraded to RFC 2119 MUST language.
- **#9 second-reviewer requirement**: release work-B1.E, B2.E, B3.E, B4.E close tickets all now explicitly require "lane owner AND a non-author reviewer" sign-off per `EVIDENCE-GATE.md` §3.3.

### R3 MINORs and OBSERVATIONs

- **#2 wording fix on receipt-v2 reverse-test**: already in correct form per the existing reverse-test description.
- **B0 OBSERVATION on sanity test**: documented as a static lint, not a fixture.
- **B1 Q5 trybuild dev-dependency**: B1.6 will need to add `trybuild` to `[dev-dependencies]` (noted in planning docs).

---

## R1 cross-cutting findings addressed

### R1 BLOCKER on line-range and trait-name drift

**Severity**: BLOCKER. **Status**: FIXED across master/template/architecture/lane-b docs.

**Summary of fix**:
- Replaced `mod.rs:1148-1165` with `mod.rs:1574-1591` (function `kernel_receipt_version_for_remote`) across ALL master/template/architecture/lane-b docs that referenced the receipt-v2 downgrade location. Every remaining `:1148-1165` mention is now in **explanatory context only** (footnotes describing the correction).
- Replaced bare `ToolServer` (when referring to the connection trait) with `ToolServerConnection` (defined at `crates/chio-kernel/src/runtime.rs:254-306`) across master/scope-lock/template docs. Lane B README's synthesis-verbatim quote is footnoted.

**Files patched**:
- `README.md`: Bar 2 receipt-v2 line range; trj4 absorption table (B0 entry); ship-bar Bar 2 expanded to four primitives.
- `EXECUTION-BOARD.md`: B0/B1/B2/B3 entries; cross-lane dependency table; closing-criteria block; status conventions.
- `SHIP-BAR-TRACKER.md`: Bar 2 (entire row).
- `SCOPE-LOCK.md`: Lane B in-scope rows; OUT-OF-SCOPE chio-cli paragraph (`ToolServer` -> `ToolServerConnection` at runtime.rs:254-306); B4 row added.
- `TIMELINE.md`: Master timeline ASCII; per-lane Lane B section; critical path; week-by-week.
- `KICKOFF-CHECKLIST.md`: "The three Bars" anchoring refrain.
- `architecture/SPEC-TO-RUNTIME-MAP.md`: §2 row for receipt-v2; §8 expanded for B4 + DSSE PAE; §14 read-in order.
- `architecture/ASYNC-KERNEL-MIGRATION.md`: §1.3 inventory; §5 diff size table.
- `architecture/RISK-REGISTER.md`: new R7 added; summary table extended.
- `templates/EVIDENCE-GATE.md`: §1.2 (Artifact B); §2.4 anti-pattern example.
- `templates/CONFORMANCE-FIXTURE-PATTERN.md`: §3.3 worked-example diff; §7 sample skeleton header; §8a B4 fixture pattern added.
- `lane-b-wiring/README.md`: Lane B duration extended to 7 weeks; B4 added to sub-lane summary; week-by-week timeline updated; synthesis quote footnoted.
- `lane-b-wiring/PLAN.md`: window updated; B4 sub-lane section added; B2 spec citation reframed.
- `lane-b-wiring/planning docs`: ticket-ID convention header; B4.1-B4.6 added; B1.E/B2.E/B3.E/B4.E added; B.CLOSE retired; ticket count summary updated.
- `lane-b-wiring/receipt-v2-failclosed.md`: spec-language framing paragraph; helper functions guidance; case enumeration.
- `lane-b-wiring/anchor-batch-async-only.md`: lint contract reframed.
- `lane-b-wiring/async-trait-migration.md`: blast-radius numbers; `&mut self` count.
- `lane-b-wiring/conformance-fixture-spec.md`: B4 fixture inventory; B4 negative-conformance pattern subsection.

**Drift verification**:

```
$ grep -rn "1148-1165" .planning/trajectory-5/ | grep -v /reviews/ | grep -v /debate/ | grep -v /lane-c-demo/
[All 7 remaining matches are explanatory context  -  footnotes that explicitly say "synthesis line 31 cited :1148-1165 which is the resolver helper, not the runtime downgrade".]

$ grep -rn "ToolServer\b" .planning/trajectory-5/ | grep -v ToolServerConnection | grep -v ToolServerOutput | grep -v ToolServerEvent | grep -v ToolServerStreamResult | grep -v /reviews/ | grep -v /debate/ | grep -v /lane-c-demo/
[Remaining matches are struct names (`EchoToolServer`, `SharedUpstreamToolServer`), method names (`register_tool_server`, `tool_server_escape`), or one synthesis-verbatim quote in lane-b-wiring/README.md that is now footnoted.]
```

The synthesis itself (`debate/00-SYNTHESIS.md`) is left as-is per the contract-not-mutated principle; the corrections live as footnotes/notes in the patched docs.

### R1 BLOCKER on DSSE not propagated -> B4 promotion (this is the new sub-lane)

**Severity**: BLOCKER. **Status**: FIXED via promotion to B4.

See "B4 sub-lane" section below.

### R1 MAJOR on Evidence-Gate ticket suffix convention

**Severity**: MAJOR. **Status**: FIXED.

**Summary of fix**: Picked the canonical `.E` suffix per sub-lane (matching `templates/TICKET-TEMPLATE.md` §38). Retired `release work-B-EG` (master shorthand) and `release work-B.CLOSE` (Lane B shorthand). Each Lane B sub-lane now carries one `.E` ticket: `release work-B1.E`, `release work-B2.E`, `release work-B3.E`, `bilateral DSSE signing item`.

**Files patched**:
- `lane-b-wiring/planning docs`: header convention paragraph added; per-primitive `.E` close tickets replace the single `B.CLOSE` aggregator.
- `EXECUTION-BOARD.md`: Lane B table entry uses `release work-B1.E` ... `bilateral DSSE signing item`; cross-lane dependency table; status conventions footer.

---

## B4 sub-lane (NEW per R4 BLOCKER 1)

**R4 BLOCKER 1**: the previously-proposed Lane C "Option A two-signature" framing was insufficient. The legacy `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share ZERO bytes with the spec §6 DSSE PAE preimage. Only the DSSE envelope is §6-conformant. R4 proposed promoting DSSE-conformant signing to a Lane B fourth primitive.

**B4 sub-lane**:
- **Title**: DSSE-conformant bilateral signing.
- **Spec citation**: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 (DSSE PAE encoding) + §7 step 11-12 (signature verification).
- **Effort**: L (3-6 days).
- **Week placement**: weeks 5-6 (starts week 5 alongside B2/B3 wrap-up; lands by end of week 6). Lane C consumes B4's PAE-conformant signing surface from week 6+.
- **Dependencies**: B0 (hard, async-trait migration); B1 (soft, single-entry verifier discipline reuse).

**Files added**:
- `lane-b-wiring/dsse-bilateral-signing.md` (NEW, ~250 lines): scope, current state of `CoSigningBody`, target wire format (PAE encoding), migration strategy (cohabitation chosen for release work; one-version-transition deferred to trj6), relationship to `DualSignedReceipt`, conformance fixture design (with code skeleton), why R4 BLOCKER 1 was a BLOCKER, out of scope for B4.

**Files updated for B4**:
- `lane-b-wiring/README.md`: sub-lane summary table; week-by-week timeline; ship-bar item count (3 -> 4).
- `lane-b-wiring/PLAN.md`: new "Sub-lane B4: DSSE-conformant bilateral signing" section.
- `lane-b-wiring/planning docs`: new bilateral DSSE signing item sub-lane (6 tickets); new bilateral DSSE signing item close ticket; ticket count summary updated 23 -> 32.
- `lane-b-wiring/conformance-fixture-spec.md`: §8a (B4 negative-conformance fixture pattern); fixture inventory table extended.
- `templates/CONFORMANCE-FIXTURE-PATTERN.md`: §1.1 lane-table extended; §8a (B4 negative-conformance pattern subsection).
- `architecture/SPEC-TO-RUNTIME-MAP.md`: §8 (Cross-Org Bilateral Cosign) extended with two new rows for §6 PAE encoding and §7 signature verification, both citing bilateral DSSE signing item
- `architecture/RISK-REGISTER.md`: new R7 (DSSE complexity); summary table extended.
- `EXECUTION-BOARD.md`: Lane B table extended with release work-B4 row; cross-lane dependency table extended (B0->B4 hard, B1->B4 soft, B4->C2 hard).
- `SHIP-BAR-TRACKER.md`: Bar 2 expanded to four primitives; evidence-required (4) row added; machine-readable signal lists four files including `bilateral_dsse_pae_only_is_conformant.rs`.
- `SCOPE-LOCK.md`: Lane B in-scope row added for B4 (per Lane A agent's auto-update).
- `README.md`: ship-bar Bar 2 expanded; trj4 absorption table extended; lane-table updated to weeks 1-7.
- `TIMELINE.md`: master timeline ASCII updated; per-lane Lane B; critical path.

**B4 ticket IDs**: bilateral DSSE signing item (wire-format design), B4.2 (`bilateral_dsse.rs` module), B4.3 (federation hot-path emission), B4.4 (legacy disclaimer doc-comment), B4.5 (negative conformance fixture), B4.6 (spec citation MUST verification). Plus bilateral DSSE signing item (Evidence Gate close ticket).

---

## Drift-fix verification

```
$ grep -rn "1148-1165" .planning/trajectory-5/ 2>/dev/null | grep -v /reviews/ | grep -v /debate/ | grep -v /lane-c-demo/
EXECUTION-BOARD.md:55:        ... (Note: synthesis line 31 cited `:1148-1165` ...)  [explanatory footnote]
SHIP-BAR-TRACKER.md:40:    ... (The synthesis line 31 cited `:1148-1165` ...)  [explanatory footnote]
README.md:75:               ... (Note: synthesis line 31 cited `:1148-1165` ...)  [explanatory footnote]
architecture/SPEC-TO-RUNTIME-MAP.md:38: ... Note: synthesis line 31 cited `:1148-1165` ...  [explanatory footnote]
templates/EVIDENCE-GATE.md:195:           `:1148-1165` which is the resolver helper ...  [explanatory footnote]
templates/CONFORMANCE-FIXTURE-PATTERN.md:252: ... Note: synthesis line 31 cited :1148-1165 ...  [explanatory footnote]
lane-b-wiring/receipt-v2-failclosed.md:36: The synthesis (line 31) cited the line range `mod.rs:1148-1165` ...  [explanatory paragraph]
```

All 7 remaining `1148-1165` matches are explanatory footnotes that explicitly describe the correction. There are zero load-bearing references to the wrong line range.

```
$ grep -rn "ToolServer\b" .planning/trajectory-5/ 2>/dev/null | grep -v ToolServerConnection | grep -v ToolServerOutput | grep -v ToolServerEvent | grep -v ToolServerStreamResult | grep -v /reviews/ | grep -v /debate/ | grep -v /lane-c-demo/
lane-a-floor/threat-evidence-backfill.md:102:     ... release work-B0 ToolServer async migration ...  [Lane A doc, NOT my scope]
lane-a-floor/planning docs:136:                       ... release work-B0 ToolServer migration ...  [Lane A doc, NOT my scope]
lane-b-wiring/conformance-fixture-spec.md:50: kernel.register_tool_server(Box::new(EchoToolServer::new()));  [method name + struct name, NOT trait]
lane-b-wiring/async-trait-migration.md:36:  the SharedUpstreamToolServer at line 2682 + 2860.  [struct name, NOT trait]
lane-b-wiring/async-trait-migration.md:65:  (the `EchoToolServer` at lines 58-77)  [struct name, NOT trait]
lane-b-wiring/README.md:11:                       [synthesis-verbatim quote with footnote correction]
lane-b-wiring/PLAN.md:39:                          (the `EchoToolServer` impl)  [struct name, NOT trait]
lane-b-wiring/single-entry-verifier.md:92:        (real `Keypair`, real `SqliteReceiptStore`, real `EchoToolServer`).  [struct name]
```

All remaining bare `ToolServer` matches in master/template/architecture/lane-b are either struct names (`EchoToolServer`, `SharedUpstreamToolServer`), method names (`register_tool_server`), or the synthesis-verbatim quote in `lane-b-wiring/README.md` (now footnoted). Lane A docs cited two `ToolServer` references in informational context; per task instructions ("Do NOT touch Lane A docs"), I did not modify them. They are flagged for the Lane A fix agent.

---

## Anything left for Wave 4 final-pass

1. **Lane A `tool_server_escape` references**: `lane-a-floor/threat-evidence-backfill.md:102` and `lane-a-floor/planning docs:136` reference "release work-B0 ToolServer async migration". These are out of my scope (Lane A fix agent's domain). They are informational context about whether the threat row defers; the trait-name correction is cosmetic but consistent.

2. **Synthesis source text**: `debate/00-SYNTHESIS.md` lines 31, 38, 95, 105 still cite `:1148-1165` and `ToolServer`. Per the task instruction, "the synthesis itself can carry a SUPERSEDED footnote rather than be rewritten." I did not add a footnote to the synthesis itself; instead, the Lane B docs and master docs all contain explicit correction-footnotes. If Wave 4 wants a SUPERSEDED stub at the synthesis, it can be added to a new file `debate/00a-errata.md` (not attempted in Wave 3 to avoid synthesis-mutation risk).

3. **Lane C agent coordination**: B4 introduces dependencies that Lane C MUST consume. Specifically:
   - Lane C C2 (capability lease + budget bond) and C1 (bilateral demo) MUST consume B4's `bilateral_dsse.rs` PAE-conformant signing surface, NOT the legacy `DualSignedReceipt`-only surface.
   - Lane C release notes MUST carry the explicit non-§6 disclaimer for `DualSignedReceipt::verify` (per B4.4).
   - The "Option A two-signature" framing in `lane-c-demo/bilateral-cosign-flow.md` is now superseded by the B4 design; Lane C agent should rewrite that doc to consume B4 rather than implement the two-signature framing.
   - Lane C's prior `LB-AT` alias (now `release work-B0.5`) and `LB-CAP`/`LB-RV2`/`LB-AB` aliases need to be replaced with literal ticket IDs (R1 finding 2.2). This is the Lane C agent's responsibility.

4. **`OWNERS.toml` overlap rows**: R1 finding 3.4 / 3.5 calls for adding `coordination_owner` to overlap rows. The overlap on `crates/chio-federation/` between B and C is now deeper because B4 lives in `chio-federation`. Wave 4 should add `coordination_owner = "release owner"` (the manifest's `single_owner`).

5. **`releases.toml` block**: R1 finding noted the block needs a `[trajectory_5]` row. Out of my Wave 3 scope.

6. **Spec edit in `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`**: B4.6 ticket assumes §6 lines 338-353 and §7 step 11-12 already contain `MUST`. If Wave 1 spec audit shows they do not, B4.6 scope expands to include the spec edit. Wave 4 verifier should confirm.

7. **B4 / Lane C release-bar.md narrative**: the existing `lane-c-demo/release-bar.md` claims the DSSE envelope conforms to §6 via the "Option A AND" framing (R4 finding 4). Lane C agent should rewrite this to "the DSSE envelope is the spec §6 conformant artifact; the legacy `DualSignedReceipt` is retained for backward compatibility but is NOT a §6 artifact" per B4.4.

---

## Cross-references

- `R3-lane-b-compliance.md`: 3 BLOCKERs, 6 MAJORs, 4 MINORs, 3 OBSERVATIONs.
- `R1-cross-lane.md`: drift-fix table at section 4.3; sample patches at Appendix A.
- `R4-lane-c-feasibility.md`: BLOCKER 1 (DSSE Option-A insufficient) is the root of B4 promotion.

End of W3 Lane B fix-log.
