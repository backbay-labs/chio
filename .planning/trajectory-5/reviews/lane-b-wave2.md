# Lane B Wave-2 Sign-Off Ledger

**Lane**: B (lane-b-wiring) -- "Wire the spec hot path".
**Original review**: `reviews/R3-lane-b-compliance.md` (Wave 2 Lane B compliance review).
**Original review verdict**: APPROVE-WITH-CHANGES (see R3 Executive summary).
**Cross-cutting review affecting Lane B**: `reviews/R1-cross-lane.md` (cross-lane), `reviews/R4-lane-c-feasibility.md` (whose BLOCKER 1 promoted Lane C "Option A" to a Lane B fourth primitive B4).
**Post-Wave-3 status**: ALL BLOCKERs CLOSED. ALL MAJORs CLOSED. New B4 sub-lane added (DSSE-conformant bilateral signing).
**Authoritative closeout reference**: `reviews/W4-closeout-matrix.md` Lane B (R3) row block.
**Sign-off recorded**: 2026-05-08 by Wave-4 final-pass agent on behalf of original Wave-2 reviewer.

This ledger is the structured per-lane sign-off artifact required by
`KICKOFF-CHECKLIST.md` "Wave-2 reviewer sign-off ledger" row. The
original Wave-2 reviewer for Lane B (R3) was an autonomous agent; per
the release work autonomous-execution context (see `OWNERS.toml` top-of-file
note), the sign-off is recorded by the Wave-4 final-pass agent against
the closeout matrix evidence.

---

## Findings closure ledger

### R3 BLOCKERs (3 of 3 CLOSED)

| Finding | Severity | Title | Closed by W3 fix-log section | Status |
|---|---|---|---|---|
| R3-BLOCKER-1 | BLOCKER | B2 spec-language framing (PROTOCOL.md §737-741 has neither MUST nor SHOULD; framing as "promotion" is wrong) | `W3-lane-b-fixes.md` § "R3 BLOCKER #1: B2 spec-language framing" | CLOSED |
| R3-BLOCKER-2 | BLOCKER | B3 lint script soundness contract unachievable (50-line-window grep heuristic) | `W3-lane-b-fixes.md` § "R3 BLOCKER #2: B3 lint script soundness contract" | CLOSED |
| R3-BLOCKER-3 | BLOCKER | B0 impl count audit (47 sites in 31 files, not 31 impls) | `W3-lane-b-fixes.md` § "R3 BLOCKER #3: B0 impl count audit" | CLOSED |

### R3 MAJORs (6 of 6 CLOSED)

| Finding | Title | Closed by W3 fix-log section | Status |
|---|---|---|---|
| R3-MAJOR-3 | Single-entry-verifier error mapping (typed deny reasons at hosted call sites) | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #3" | CLOSED |
| R3-MAJOR-1-reservation | B2 helper functions read SQLite tables directly, not via test-only kernel accessor | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #1 reservation" | CLOSED |
| R3-MAJOR-4-stale-vs-never-pinned | B2 spec edit explicitly enumerates both "stale" and "never-pinned" cases | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #4 last paragraph" | CLOSED |
| R3-MAJOR-5 | B3 gate-script soundness (subsumed by R3-BLOCKER-2) | Same as R3-BLOCKER-2 (Option A: honest reframing; lint is fast-feedback) | CLOSED |
| R3-MAJOR-6 | B0 impl count audit (subsumed by R3-BLOCKER-3) | Same as R3-BLOCKER-3 | CLOSED |
| R3-MAJOR-7 | Spec MUST citations (B3 promotion of arrow notation) | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #7" | CLOSED |
| R3-MAJOR-9-second-reviewer | Second-reviewer requirement on close tickets | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #9" | CLOSED |

### R3 MINORs / OBSERVATIONs (informational; not gating)

R3-MINOR-2 (wording fix on receipt-v2 reverse-test): already correct.
B0 OBSERVATION on sanity test: documented as static lint, not a fixture.
B1 Q5 trybuild dev-dependency: B1.6 will add `trybuild` to
`[dev-dependencies]`. All addressed in `W3-lane-b-fixes.md` § "R3 MINORs
and OBSERVATIONs".

### R1 cross-lane BLOCKERs/MAJORs affecting Lane B (5 CLOSED)

| Finding | Severity | Title | Closed by | Status |
|---|---|---|---|---|
| R1-BLOCKER-4.3 | BLOCKER | Master / template / architecture / Lane C docs cite pre-correction line range `mod.rs:1148-1165` and trait name `ToolServer` | `W3-lane-b-fixes.md` § "R1 BLOCKER on line-range and trait-name drift" (full file inventory in W3 fix log) | CLOSED |
| R1-MAJOR-2.1 | MAJOR | Three different Evidence-Gate ticket suffix conventions (`release work-B-EG`, `release work-B.CLOSE`, `release work-B<n>.E`) | `W3-lane-b-fixes.md` § "R1 MAJOR on Evidence-Gate ticket suffix convention" | CLOSED |
| R1-MAJOR-7.3 | MAJOR | Lane B / Lane C tickets lack trj4 back-references | Lane B planning docs carries `trj4_absorbed` columns at sub-lane summary; OWNERS.toml `trj4_absorbed = [...]` lane-B row | CLOSED |
| R4-BLOCKER-1 | BLOCKER (R4 origin; affects Lane B) | DSSE Option-A two-signature insufficient -- promote DSSE-conformant signing to a Lane B fourth primitive (B4) | `W3-lane-b-fixes.md` § "B4 sub-lane (NEW per R4 BLOCKER 1)" -- adds B4.1..B4.6 plus B4.E close ticket | CLOSED |

### Wave-4 residual coordination items affecting Lane B (CLOSED in W4)

| W4 item | Title | Status |
|---|---|---|
| 2 | R7 RISK-REGISTER row reframed for new B4 risk (DSSE PAE encoding, Ed25519 over PAE fragility) | CLOSED (already correctly framed by Lane B Wave 3 fix agent; Wave 4 verified) |
| 3 | KB MCP `mcp-remote` bridge in Lane B conformance fixture spec | CLOSED (Wave 4 added "Lane C demo path note" subsection to `conformance-fixture-spec.md`) |
| 5 | OWNERS.toml `coordination_owner` for `crates/chio-federation/` (B4 ↔ Lane C C2 path overlap) | CLOSED (Wave 4 converted `[overlaps]` rows to inline tables with `coordination_owner` field; chio-federation row carries `path_overlaps` and `notes`) |

---

## Reviewer sign-off block

**Reviewer of record (Wave 2)**: Lane B compliance reviewer (autonomous
agent), posture: "Protocol Realization Engineer perspective" per R3
header.

**Sign-off agent (Wave 4 final-pass, recorded 2026-05-08)**: this
ledger is countersigned by the Wave-4 final-pass agent on behalf of the
original Wave-2 reviewer. The autonomous-execution context (OWNERS.toml
top-of-file note) means each reviewer-agent is bound by the same
closeout discipline as a human reviewer, and the Wave-3 fix logs plus
the Wave-4 closeout matrix together constitute the structured sign-off
evidence.

All R3 BLOCKERs (3) and MAJORs (6) are CLOSED per `W4-closeout-matrix.md`
R3 row block. The cross-lane R1-BLOCKER-4.3 (line-range/trait-name
drift) is CLOSED. R4-BLOCKER-1 -- which restructured Lane B by adding
the B4 sub-lane (DSSE-conformant bilateral signing) -- is CLOSED.

Verdict: **APPROVED for kickoff execution**. Lane B is cleared to begin
B0 (async-trait migration) immediately upon kickoff. B1, B2, B3, and
B4 are gated on B0 landing per the dependency graph in
`lane-b-wiring/README.md` "Sub-lane summary" table.

---

## Outstanding pre-execution gates (informational; tracked elsewhere)

These items are NOT BLOCKERs to kickoff -- they are tracked in the
`KICKOFF-CHECKLIST.md` and the W3 Lane B fix-log "Anything left for
Wave 4 final-pass" list. Listed here so the lane execution agent enters
Wave 1 with eyes open:

1. **B0 must land before B1, B2, B3, B4 begin**. The dependency graph
   in `lane-b-wiring/README.md` is hard: `ToolServerConnection` async
   migration is the architectural prerequisite. B1-B4 wave starts in
   week 3 (B1) / weeks 4-5 (B2/B3) / weeks 5-6 (B4) per the week-by-week
   timeline.

2. **B4 spec edit dependency**. bilateral DSSE signing item ticket assumes
   `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 and
   §7 step 11-12 already contain `MUST`. If Wave 1 spec audit shows
   they do not, B4.6 scope expands to include the spec edit. (W3 Lane
   B fix-log "Anything left for Wave 4" item 6.)

3. **Lane C ↔ B4 coordination**. Lane C C2 (capability lease + budget
   bond) and Lane C C1 (bilateral demo) MUST consume B4's
   `bilateral_dsse.rs` PAE-conformant signing surface. Lane C
   docs already swept; OWNERS.toml `crates/chio-federation/` overlap
   row carries `coordination_owner = "release owner"` and `path_overlaps`
   list including `bilateral_dsse.rs`. Merge order is mediated by the
   coordination owner.

4. **Lane A ↔ B0 coordination on `chio-anchor`**. R2-MINOR-8.3 noted
   that Lane B may modify `crates/chio-anchor/src/batch.rs` during
   release work-B3 in ways that change the shape of `verify_anchor_batch`. The
   Lane A Kani harness depends on this shape. The coordination note is
   in place in `lane-a-floor/kani-harness-design.md`.

5. **`spec/PROTOCOL.md` line edits**. B1, B2, B3 each ship a spec edit
   (B1: SHOULD->MUST at PROTOCOL.md line 408; B2: tightening NEW MUST
   at lines 737-741; B3: arrow-notation upgrade per §6.4.1). The audit
   doc evidence section for each of B1.E, B2.E, B3.E checks the
   corresponding line range against merged-branch HEAD per
   `templates/EVIDENCE-GATE.md` §1.2. (W3 Lane B fix-log "Anything left
   for Wave 4" item 6.)

6. **Conformance-fixture-spec MCP bridge note**. The `mcp-remote`
   bridge note added to `lane-b-wiring/conformance-fixture-spec.md`
   per W4 item 3 documents how the Lane B conformance pattern
   accommodates the Lane C demo's HTTP-MCP bridge. The lane-execution
   agent should preserve this note when extending the spec.

7. **Second-reviewer on close tickets**. Per R3-MAJOR-9, every Lane B
   close ticket (B1.E, B2.E, B3.E, B4.E) requires lane owner AND a
   non-author reviewer sign-off per `EVIDENCE-GATE.md` §3.3. In
   autonomous-execution mode, the "non-author reviewer" is a separate
   agent run; the human escalation path is `release owner`.

8. **Cohabitation transition for B4**. `lane-b-wiring/dsse-bilateral-signing.md`
   chooses cohabitation for release work (legacy `CoSigningBody` retained as
   fixture-only signer; production hot path emits DSSE PAE envelope by
   default). One-version-transition deferred to trj6.

---

## Final approval line

**LANE B WAVE-2 SIGN-OFF**: APPROVED for release work kickoff execution.
**Recorded**: 2026-05-08 by Wave-4 final-pass agent.
**Authority**: `reviews/W4-closeout-matrix.md` (3 R3 BLOCKERs + 6 R3
MAJORs + R1-BLOCKER-4.3 + R4-BLOCKER-1 all CLOSED; B4 sub-lane added).
**Pre-execution gates**: 8 informational items above; none gate
kickoff. All routed through autonomous waves under
`human_assignment = "release owner"`.

End of Lane B Wave-2 sign-off ledger.
