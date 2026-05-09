# Lane C Wave-2 Sign-Off Ledger

**Lane**: C (lane-c-demo) -- "One forcing demo".
**Original review**: `reviews/R4-lane-c-feasibility.md` (Wave 2 Lane C feasibility review).
**Original review verdict**: APPROVE-WITH-CHANGES; specifically rejected the W1 "Option A two-signature DSSE adapter" framing as structural-without-wiring (R4 BLOCKER 1).
**Cross-cutting review affecting Lane C**: `reviews/R1-cross-lane.md` (cross-lane).
**Post-Wave-3 status**: ALL BLOCKERs CLOSED. ALL MAJORs CLOSED. Lane C reworked to consume Lane B B4 (DSSE-conformant bilateral signing) instead of implementing Option A.
**Authoritative closeout reference**: `reviews/W4-closeout-matrix.md` Lane C (R4) row block.
**Sign-off recorded**: 2026-05-08 by Wave-4 final-pass agent on behalf of original Wave-2 reviewer.

This ledger is the structured per-lane sign-off artifact required by
`KICKOFF-CHECKLIST.md` "Wave-2 reviewer sign-off ledger" row. The
original Wave-2 reviewer for Lane C (R4) was an autonomous agent; per
the release work autonomous-execution context (see `OWNERS.toml` top-of-file
note), the sign-off is recorded by the Wave-4 final-pass agent against
the closeout matrix evidence.

---

## Findings closure ledger

### R4 BLOCKERs (2 of 2 CLOSED)

| Finding | Severity | Title | Closed by W3 fix-log section | Status |
|---|---|---|---|---|
| R4-BLOCKER-1 | BLOCKER | DSSE/Ed25519 signing scheme -- "Option A" two-signature design does not satisfy spec §6 | `W3-lane-c-fixes.md` § "R4 BLOCKER 1 (DSSE signing scheme - Option A insufficient) - REWORKED" + `W3-lane-b-fixes.md` § "B4 sub-lane (NEW per R4 BLOCKER 1)". Option A dropped entirely; promoted to Lane B sub-lane B4 (bilateral DSSE signing item + B4.E). Lane C consumes B4 envelope, ships `predicate_from_kernel_state` helper, §7 verifier, `CapabilityVerifier` trait. | CLOSED |
| R4-BLOCKER-2 | BLOCKER | KB MCP transport mismatch (`chio mcp serve` wraps stdio; KB MCP serves HTTP) | `W3-lane-c-fixes.md` § "R4 BLOCKER 2 (KB MCP HTTP/stdio bridge) - RESOLVED". Demo uses `mcp-remote` (Node.js stdio<->HTTP bridge per `ops/knowledge-base/README.md:136-151`) as wrapped command. Pre-requisites section + HushSpec policy YAML rewrite. | CLOSED |

### R4 MAJORs (8 of 8 CLOSED)

| Finding | Title | Closed by W3 fix-log section | Status |
|---|---|---|---|
| R4-MAJOR-3 | Cross-lane dep aliases (`LB-CAP`, `LB-RV2`, `LB-AB`, `LB-AT`) not anchored to Lane B IDs | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 3". Aliases replaced with literal Lane B ticket IDs in `Depends on` rows; alias->ID map preserved in documentation table. | CLOSED |
| R4-MAJOR-4 | release-bar.md AND-overclaims §6 conformance | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 4". Release notes cite Lane B B4 directly; new items 13/14 in "What this release DOES NOT CLAIM". | CLOSED |
| R4-MAJOR-5a | chiodos-ladder primitive missing in code | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 5a". release work-C1.3 effort bumped M->L; primitive lives in `examples/chiodome-bilateral/src/ladder.rs`; production primitive deferred to trj6. | CLOSED |
| R4-MAJOR-5b | Policy YAML format mismatch | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 5b". Policy YAML rewritten in HushSpec shape; amount cap moved to ladder intersection per option (a). | CLOSED |
| R4-MAJOR-6 | BBS+ deps absent; R6 mitigation soft | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 6". Explicit deferral path: C5 ships only if W2 dep-tree validation succeeds; otherwise five-artifact bundle. | CLOSED |
| R4-MAJOR-7 | End-to-end composition gaps (anchor inclusion proof; two-keypair signing) | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 7". New release work-C2.5 ticket (anchor inclusion proof); §7 verifier ticket release work-C2.4 depends on B1.6/B2.5/B3.5/B4.5; two-keypair signing protocol section. | CLOSED |
| R4-MAJOR-8 | 17-step verifier cross-crate calls (steps 7, 14) unresolved | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 8". Architecture cut option B (trait objects for `ReceiptStore` and `CapabilityVerifier`); release work-C2.1 introduces `CapabilityVerifier` trait in `chio-federation`. | CLOSED |
| R4-MAJOR-10 | Forcing-function CI hook missing | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 10". release work-C6.3 "Continuous chiodome demo workflow" added (nightly + Lane B path push, failures open issues, 7 consecutive nights green pre-tag). | CLOSED |

### R4 MINORs / OBSERVATIONs (informational; not gating)

R4-MINOR-9 (`chio receipt explain` underestimated): release work-C4.1 bumped
M->L; explain output's "policy verdict disagreement" surfaced as
top-level diagnostic. R4-MINOR-11 (demo fixture reproducibility): new
release work-C6.4 "Diff-stable fixture tarball" with `tools/diff-stable.py`.
R4-MINOR-12 (mock-receipt detection): release work-C6.2 mtime check.
R4-OBSERVATION-14 (ticket count 30->24 within R1 §11.7 22-26 range).
All addressed in `W3-lane-c-fixes.md` § "R4 MINORs" + § "R4
OBSERVATIONs".

### R1 cross-lane BLOCKERs/MAJORs affecting Lane C (4 CLOSED)

| Finding | Severity | Title | Closed by | Status |
|---|---|---|---|---|
| R1-BLOCKER-1.4 | BLOCKER | Lane C "Option A" DSSE adapter invisible above the Lane C deep dive (master-doc surfacing) | `W3-lane-b-fixes.md` § "B4 sub-lane (NEW per R4 BLOCKER 1)" + `W3-lane-c-fixes.md` § "R4 BLOCKER 1 - REWORKED". Master docs (SHIP-BAR-TRACKER, SCOPE-LOCK, SPEC-TO-RUNTIME-MAP, RISK-REGISTER R7) updated with B4 row. | CLOSED |
| R1-BLOCKER-2.2 | BLOCKER | Lane C uses non-template aliases instead of literal Lane B ticket IDs | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 3". | CLOSED |
| R1-BLOCKER-5.3 | BLOCKER | Lane C tickets contain zero Evidence Gate references and zero TRJ4 back-references | `W3-lane-c-fixes.md` § "R1 BLOCKER (Lane C zero Evidence Gate references) - RESOLVED". Lane C tickets rewritten with five-row Acceptance block per ticket plus header paragraph. | CLOSED |
| R1-MAJOR-6.2 | MAJOR | R4 mitigation (continuous Lane C smoke) contradicts the timeline (Lane C deferred until W4) | `W3-lane-c-fixes.md` § "R1 MAJOR (continuous Lane C run) - RESOLVED". Lane C scaffolding (C1.1, C1.2, C1.4) starts W3 alongside in-progress Lane B; new C6.3 continuous workflow ticket. | CLOSED |
| R1-MAJOR-1.3 | MAJOR | Lane C5 (selective disclosure) scope creep through new workspace member `chio-zk-receipts` and BBS+ deps | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 6". Explicit deferral path; bounded-claim language landed in `release-bar.md` and `selective-disclosure.md`. | CLOSED |

### Wave-4 residual coordination items affecting Lane C (CLOSED in W4)

| W4 item | Title | Status |
|---|---|---|
| 1 | Lane C placeholder `bilateral DSSE signing item` deps replaced with locked B4 IDs (B4.1..B4.6 plus B4.E) | CLOSED (Wave 4 patched bilateral-cosign-flow.md, release-bar.md, README.md, PLAN.md, planning docs) |

---

## Reviewer sign-off block

**Reviewer of record (Wave 2)**: Lane C feasibility reviewer
(autonomous agent), posture: "Vision Strategist's most ruthless
internal critic" per R4 header.

**Sign-off agent (Wave 4 final-pass, recorded 2026-05-08)**: this
ledger is countersigned by the Wave-4 final-pass agent on behalf of the
original Wave-2 reviewer. The autonomous-execution context (OWNERS.toml
top-of-file note) means each reviewer-agent is bound by the same
closeout discipline as a human reviewer, and the Wave-3 fix logs plus
the Wave-4 closeout matrix together constitute the structured sign-off
evidence.

All R4 BLOCKERs (2) and MAJORs (8) are CLOSED per `W4-closeout-matrix.md`
R4 row block. The cross-lane R1 BLOCKERs/MAJORs affecting Lane C
(R1-BLOCKER-1.4, R1-BLOCKER-2.2, R1-BLOCKER-5.3, R1-MAJOR-6.2,
R1-MAJOR-1.3) are CLOSED. R4-BLOCKER-1 (DSSE Option A insufficient)
restructured the release work plan: Option A is dropped; DSSE-conformant
bilateral signing lives in Lane B as sub-lane B4; Lane C consumes B4.

Verdict: **APPROVED for kickoff execution**. Lane C is cleared to begin
W3 scaffolding (C1.1, C1.2, C1.4) immediately upon kickoff. The bulk
of Lane C (especially C2: §7 verifier + predicate helper) waits on
Lane B B4 landing in week 5-6 of Lane B execution.

---

## Outstanding pre-execution gates (informational; tracked elsewhere)

These items are NOT BLOCKERs to kickoff -- they are tracked in the
`KICKOFF-CHECKLIST.md` and the W3 Lane C fix-log "Anything for Wave 4
final-pass" list. Listed here so the lane execution agent enters
Wave 3 (when Lane C scaffolding starts) with eyes open:

1. **Lane C waits on Lane B B4 landing** before C2 (§7 verifier +
   predicate helper) can compose end-to-end. Per
   `lane-c-demo/README.md` and the Lane B week-by-week timeline,
   B4 lands week 5-6 of Lane B execution; Lane C C2 starts week 6.
   Lane C scaffolding (C1.1 example skeleton, C1.2 chiodos-ladder
   stub, C1.4 ticketing) starts W3 in parallel with Lane B B0->B1.

2. **`mcp-remote` bridge in CI**. release work-C3.2 wraps the command
   `chio mcp serve --policy ... -- npx -y mcp-remote
   http://localhost:8111/mcp/`. Air-gapped CI runners must pre-warm
   the npm cache; pre-requisite "Node.js / npx available in the smoke
   container" recorded in release work-C3.2 ticket.

3. **Spec line-range citations to fill in**. Several Lane C tickets
   cite `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6/§7 line ranges
   as "lines to be filled in by audit-doc owner". W3 Lane C fix-log
   "Anything for Wave 4" item 2 acknowledged Wave 4 fills these in;
   W4 closeout matrix records all Lane C placeholders swept to
   locked B4 IDs but spec line ranges may still need confirmation.

4. **Anchor inclusion proof emission** (release work-C2.5; R4 Step gap 7a). New
   ticket per R4-MAJOR-7. Effort M; depends on B1.6/B2.5/B3.5/B4.5
   landing.

5. **Two-keypair signing protocol** (Step gap 7c; in
   `bilateral-cosign-flow.md`). Each kernel signs its own PAE; existing
   `CoSigningRequest`/`Response` cadence is generalised by B4. Lane C
   ticket `release work-C1.x` consumes the B4 protocol; the Lane C agent must
   not re-implement the cadence.

6. **CapabilityVerifier trait in `chio-federation`** (release work-C2.1; R4
   MAJOR 8 architecture cut option B). The verifier in `chio-federation`
   does not pull in `chio-kernel` directly. The trait lives next to
   `bilateral_dsse.rs`; Lane B ↔ Lane C path overlap is mediated by
   the OWNERS.toml `crates/chio-federation/` `coordination_owner`.

7. **C5 (selective disclosure) deferral path**. C5 ships only if W2
   dep-tree validation succeeds for BBS+ deps. Otherwise C5 drops to
   five-artifact bundle. `release-bar.md` item 14 enumerates the
   deferral.

8. **Continuous chiodome demo workflow** (release work-C6.3;
   `.github/workflows/chiodome-demo-continuous.yml`). Nightly + Lane B
   path-push triggers; failures open issues; 7 consecutive nights green
   pre-tag.

9. **Diff-stable fixture rule** (release work-C6.4). The smoke step 5 calls
   `tools/diff-stable.py` (or Rust binary); the rule is "diff-stable
   across runs", not "byte-identical".

10. **Bounded canary package status**. `releases.toml`
    `[v0_1_0_bounded_chiodome].release_status` moves only after Lane B
    integration, regenerated canary fixtures from merged `main`, and matching
    `chio receipt explain` golden output.

---

## Final approval line

**LANE C WAVE-2 SIGN-OFF**: APPROVED for release work kickoff execution.
**Recorded**: 2026-05-08 by Wave-4 final-pass agent.
**Authority**: `reviews/W4-closeout-matrix.md` (2 R4 BLOCKERs + 8 R4
MAJORs + 5 R1-Lane-C-affecting BLOCKERs/MAJORs all CLOSED; Option A
dropped; Lane C consumes Lane B B4).
**Pre-execution gates**: 10 informational items above; none gate
kickoff. All routed through autonomous waves under
`human_assignment = "release owner"`.

End of Lane C Wave-2 sign-off ledger.
