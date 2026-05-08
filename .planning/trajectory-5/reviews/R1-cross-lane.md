# R1 Cross-Lane Review

**Reviewer**: Wave 2 cross-lane reviewer
**Date**: 2026-05-07
**Scope**: master release work docs + per-lane PLAN.md / planning docs / templates / architecture
**Mode**: review only. No planning files were modified by this reviewer; Wave 3 fix agents own the patches.

## Executive summary

- The synthesis contract is broadly honored at the lane PLAN.md tier. The two largest defects sit upstream of the lane plans: master docs still cite the pre-correction line ranges and trait names that the Lane B agent corrected (`mod.rs:1148-1165` instead of `:1574-1591`; `ToolServer` instead of `ToolServerConnection`).
- Lane C silently dropped `TRJ4-019` (proptest hosted-vs-portable equivalence) by reusing the `release work-A5` slot for Lean4 work; the equivalence sub-lane is missing from `lane-a-floor/planning docs` entirely. This is a SCOPE-LOCK violation: the trj4 wave item was promised to be absorbed and is not.
- The Lane C Option-A "two-signature" decision over DSSE PAE is documented only in the Lane C deep-dive; it does not surface in master ship-bar, scope-lock, spec-to-runtime map, or risk register. This violates the Evidence Gate "Spec MUST citation" rule (Artifact B) for Lane C unless it is escalated and absorbed into the master plan.
- Ticket-ID conventions diverge across three docs (`release work-B-EG` vs `release work-B.CLOSE` vs `release work-B1.E`/`release work-B2.E`/`release work-B3.E`). The TICKET-TEMPLATE specifies the `.E` suffix and zero-padded `.y` (e.g. `release work-B1.03`); no lane file follows that convention. Lane C uses non-template aliases (`LB-CAP`, `LB-RV2`, `LB-AB`, `LB-AT`) for cross-lane dependency expression instead of literal ticket IDs.
- The Evidence Gate four-artifact rule is well-internalized in Lane B. Lane A loosely complies (per-sublane "close-bar artifact" rows). Lane C tickets contain zero references to the Evidence Gate and zero TRJ4 back-references; this is a structural compliance gap.

Verdict: **APPROVED-WITH-FIXES**. The shape of the release work plan is correct and matches the synthesis. The defects below are mechanical and are fixable in Wave 3 without re-opening the synthesis. Bar 2 cannot pass external audit until the line-range and trait-name drift is corrected.

---

## 1. Contract drift (synthesis OUT-OF-SCOPE policing)

### 1.1 Lane A (mostly clean)

OBSERVATION. Lane A planning docs does not silently extend scope. Sub-lanes A1-A5 each map to a synthesis line and a trj4 wave item. No mention of trust-control extraction, gravity-well surgery, reqwest unification, new chiodos drafts, web3 live activation.

### 1.2 Lane B (clean)

OBSERVATION. `lane-b-wiring/PLAN.md` and planning docs constrain themselves to B0/B1/B2/B3 plus the close ticket. `lane-b-wiring/README.md:57-66` re-asserts the OUT-OF-SCOPE list verbatim. No synthesis violation.

### 1.3 Lane C: scope creep risk through C5 (selective disclosure)

MAJOR. `lane-c-demo/planning docs:296-359` (sub-lane C5) introduces a new workspace member `crates/chio-zk-receipts/`, a `bbs-rs` (or equivalent) dependency, BBS+ projection types `chio.bbs-projection.workflow.v1` and `chio.bbs-projection.step.v1`, and a `chio.selective-disclosure-proof.v1` envelope. The synthesis (line 127) admits the auditor view "behind `zk` Cargo feature flag" with "no new spec ratification". Lane C5 ships:

- Spec-section interpretations of `CHIODOS_SELECTIVE_DISCLOSURE.md` sections 5.2, 6.1, 6.2, 6.4, 7.3, 8, 9 with bit-for-bit reproducibility claims ("Spec section 6.4 worked example reproduces bit-for-bit on a known fixture", `planning docs:319`).
- A new ZK dependency tree.
- A new workspace member.

Whether this is a "no new normative draft" depends on whether the BBS+ ciphersuite text in `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` is fully drafted today. R6 in `architecture/RISK-REGISTER.md:228-263` already flags the cargo-dep weight risk and proposes dropping C4 if CI hits a 5-minute or MSRV-bump threshold. R6 does not flag the spec-text question.

**Proposed fix** (Wave 3):
- `lane-c-demo/planning docs:296-359` MUST cite the exact `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` line ranges that already define the projections, ciphersuite, and envelope. If those line ranges contain `TBD` markers or are draft-shaped, C5 should note "section X.Y MUST land before release work-C5.2 closes" and the spec-stabilization work belongs in Lane C as an explicit ticket OR the section is moved to trj6.
- `architecture/RISK-REGISTER.md:228-263` (R6) should add an "is the spec text load-bearing for release work?" question to the escalation criteria. If the spec text is in flux, R6 fires and C4/C5 are bounded-claim only.

### 1.4 Lane C: bilateral DSSE adapter (Option A)

BLOCKER. `lane-c-demo/bilateral-cosign-flow.md:77-110` documents the Option-A choice: existing `CoSigningBody`-scoped Ed25519 plus new PAE-scoped Ed25519, two signatures sharing the same passport keypair. The synthesis (line 122-123) says "Per `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6". Section 6 of that spec mandates DSSE PAE. Today `crates/chio-federation/src/bilateral.rs::DualSignedReceipt` carries an Ed25519 signature over `canonical_bytes(CoSigningBody)`. Option A keeps both signatures coexisting so existing verifiers do not break; Option B rebakes the surface.

The decision is not a contract drift in itself; it is a sensible bounded-claim choice. The defect is that **the decision is invisible above the Lane C deep-dive**:

- `architecture/SPEC-TO-RUNTIME-MAP.md:97` row "DualSignedReceipt MUST carry both signers' attestations" notes the existing primitive without acknowledging the DSSE PAE gap.
- `SHIP-BAR-TRACKER.md:51-65` (Bar 3) does not name the two-signature surface.
- `SCOPE-LOCK.md:35-42` has no Lane C row that notes "DSSE PAE adapter co-existing with `CoSigningBody` signature".
- `architecture/RISK-REGISTER.md` carries no R7 for "if Option B becomes necessary, Lane C scope expands materially".

This violates the Evidence Gate Artifact B rule (`templates/EVIDENCE-GATE.md:44-58`): every Lane C primitive ticket must cite a spec MUST. The release work-C2.3, release work-C2.4 tickets cite `spec section 6 lines 338-343` (`planning docs:108-110`) but do not surface that the existing `DualSignedReceipt` is signed over a different preimage. A reviewer skimming SHIP-BAR-TRACKER will not see this. The risk is "Bar 3 closes with the DSSE adapter green and the `DualSignedReceipt` co-existing, but a future verifier audit asks 'which signature is canonical?' and the answer requires reading a Lane C deep-dive".

**Proposed fix** (Wave 3):
- `architecture/SPEC-TO-RUNTIME-MAP.md` add a row under section 8 (Cross-Org Bilateral Cosign): "Option A: two co-existing Ed25519 signatures (existing `CoSigningBody` preimage + new DSSE PAE preimage). Cross-reference `lane-c-demo/bilateral-cosign-flow.md:77-110`."
- `SHIP-BAR-TRACKER.md` Bar 3 "Evidence required" row: add an item "(9) Both signatures verify independently; the DSSE envelope adapter does not replace `DualSignedReceipt::verify`."
- `SCOPE-LOCK.md` Lane C in-scope table: add a sub-row for "DSSE PAE adapter co-existing with `CoSigningBody`-scoped Ed25519. Option B (replace signing surface) is OUT-OF-SCOPE for release work; deferred to trj6 contingent on spec-WG resolution."
- `architecture/RISK-REGISTER.md` add R7: "If during Lane C implementation the Option-A two-signature design is rejected by spec WG (e.g. they require Option B for downstream consumers), Lane C scope expands and Bar 3 may slip. Mitigation: cap Lane C2 effort at L; if Option B becomes necessary, escalate to review for a synthesis amendment."

---

## 2. Ticket-ID collisions and convention drift

### 2.1 Three different Evidence-Gate ticket suffixes

MAJOR. The same closing artifact carries three names across the planning set:

| Doc | Lane B closer | Lane C closer |
|---|---|---|
| `EXECUTION-BOARD.md:54` | `release work-B-EG` | `release work-C6` (no `.E` suffix; treated as a regular ticket) |
| `lane-b-wiring/planning docs:51` | `release work-B.CLOSE` | n/a |
| `architecture/SPEC-TO-RUNTIME-MAP.md` | `release work-B1.E`, `release work-B2.E`, `release work-B3.E` (one per primitive) | `release work-C1.E`, `release work-C2.E`, `release work-C3.E`, `release work-C4.E` |
| `templates/TICKET-TEMPLATE.md:38` | "Evidence Gate tickets use the `.E` suffix" | one `.E` ticket per sub-lane |
| `templates/EVIDENCE-GATE.md:264` | "(`### release work-X.y`)" pattern | same |

`scripts/check-release work-evidence-gate.sh` (a Wave 1 deliverable per `templates/EVIDENCE-GATE.md:283`) will parse the audit doc; it cannot find evidence under `release work-B-EG` or `release work-B.CLOSE` if the convention is `release work-B1.E` / `release work-B2.E` / `release work-B3.E`. The script either fails universally, or it parses the wrong shape, or the convention silently drifts during execution.

**Proposed fix** (Wave 3):
- Pick ONE convention. Recommended: per the TICKET-TEMPLATE, `release work-X.E` per sub-lane (so `release work-B1.E`, `release work-B2.E`, `release work-B3.E`, `release work-C1.E`, ... `release work-C6.E`). Drop `release work-B-EG` and `release work-B.CLOSE`.
- `EXECUTION-BOARD.md:54` rewrite the row as "`release work-B1.E`, `release work-B2.E`, `release work-B3.E` Evidence Gate per primitive" (three separate rows or one aggregator row clearly named).
- `lane-b-wiring/planning docs:47-51` rename `release work-B.CLOSE` to `release work-B-EG` or split into three `.E` tickets.
- `templates/TICKET-TEMPLATE.md:38` is the contract; the lane files conform to it.

### 2.2 Lane C uses non-template aliases for cross-lane dependencies

MAJOR. `lane-c-demo/planning docs:9-13` introduces:

```
- `LB-CAP` = Lane B single-entry capability verifier
- `LB-RV2` = Lane B receipt-v2 hot-path fail-closed
- `LB-AB`  = Lane B anchor-batch async-only when public witness required
- `LB-AT`  = Lane B `ToolServer` -> `async_trait` migration
```

These are **not** ticket IDs. They are aliases. The actual ticket IDs are `release work-B1.6` (negative conformance fixture for B1), `release work-B2.5`, `release work-B3.5`, `release work-B0.5` (collapse hop). `EXECUTION-BOARD.md:65,67-70` cross-lane dependency table uses literal `release work-B1`, `release work-B2`, `release work-B3` (sub-lane level, not ticket level). `architecture/SPEC-TO-RUNTIME-MAP.md` uses `release work-B1.E`/`release work-B2.E`/`release work-B3.E` (sub-lane Evidence Gate level).

This means Lane C's "depends on `LB-CAP`" cannot be machine-checked against either the master board or the Lane B tickets. A Wave-3 Evidence-Gate script cannot resolve "LB-CAP" to a ticket.

**Proposed fix** (Wave 3):
- `lane-c-demo/planning docs:9-13` replace aliases with literal ticket IDs:
  - `LB-CAP` -> `release work-B1.6` (the B1 negative conformance fixture is the gating artifact for "single-entry verifier landed").
  - `LB-RV2` -> `release work-B2.5`.
  - `LB-AB`  -> `release work-B3.5`.
  - `LB-AT`  -> `release work-B0.5` (the dispatch hop collapse is the gating artifact).
- Every C ticket's "Depends on" row uses the literal IDs.

### 2.3 Lane A swaps sub-lane numbers

MAJOR. Master `EXECUTION-BOARD.md:33-39` lists:

| ID | Title |
|---|---|
| release work-A1 | mutation kill |
| release work-A2 | threat coverage 21 rows |
| release work-A3 | Kani harnesses (3 crates) |
| release work-A4 | TLA+ rewrites |
| release work-A5 | proptest hosted-vs-portable equivalence (TRJ4-019) |
| release work-A6 | Lean4 negotiation_safety |
| release work-A7 | README banner |

`lane-a-floor/planning docs:14-158` renumbers:

| ID | Title |
|---|---|
| mutation evidence item | mutation kill |
| threat evidence item | threat coverage 20 rows |
| Kani harness evidence..5 | Kani harnesses |
| release work-A4.1..5 | TLA+ rewrites |
| release work-A5.1..4 | **Lean4 negotiation_safety** (NOT equivalence-tests) |
| (no A6) | (the Lean slot was promoted to A5; TRJ4-019 equivalence-tests has nowhere) |
| (no A7) | (the README banner is folded into mutation evidence item) |

The `chio-equivalence-tests` proptest hosted-vs-portable equivalence work (TRJ4-019, the synthesis line 38, `EXECUTION-BOARD.md:37`) is **completely missing** from Lane A. `lane-a-floor/README.md:38-44` "Sub-lane summary" table does not list it. Searching `lane-a-floor/*.md` for `TRJ4-019` or `equivalence` returns zero matches.

This is a synthesis-contract violation. The synthesis (00-SYNTHESIS.md line 88) explicitly names equivalence-tests as part of Lane A's floor.

**Proposed fix** (Wave 3):
- `lane-a-floor/planning docs` add a new sub-lane `release work-A5` (renumber the Lean4 work to `release work-A6` to match `EXECUTION-BOARD.md`), with tickets covering: chio-equivalence-tests configuration, 10k cases per PR, 1M nightly, zero divergence assertion, evidence committed.
- `lane-a-floor/README.md:38-44` add the row.
- The Lane A timeline (`README.md:64-79`) accommodates the equivalence work in week 6-8 alongside Kani.
- Alternatively if the agent intended to renumber, every master doc must follow: `EXECUTION-BOARD.md:33-39`, `OWNERS.toml:45`, `KICKOFF-CHECKLIST.md:65`. (The renumbering option is fragile; recommended is to honor the master numbering.)

### 2.4 release work-A0 referenced but not enumerated

MINOR. `lane-a-floor/planning docs:19` shows `mutation evidence item` depends on "preflight" and notes "Carry-forward of TRJ4-010". `architecture/ASYNC-KERNEL-MIGRATION.md:151` mentions `release work-A0.00` and `release work-A0.01..0.0N` (the implementer enumeration ticket). No master doc enumerates an A0 sub-lane. EXECUTION-BOARD.md:33 has a "release work-A0 (preflight)" reference under release work-A1's depends-on.

**Proposed fix** (Wave 3):
- Either enumerate release work-A0 as a Wave-0 preflight sub-lane row in `lane-a-floor/planning docs` and `EXECUTION-BOARD.md`, OR drop the references and inline-document the preflight as part of mutation evidence item
- Note: ASYNC-KERNEL-MIGRATION.md:151,160-188 misuses `A0.00`, `A0.01` etc. for Lane B work; those should be `B0.0`, `B0.1`, etc. (Lane B0 sub-lane). Confirm by reading `lane-b-wiring/planning docs:5-15` which uses `release work-B0.1..6`.

### 2.5 TICKET-TEMPLATE zero-pad convention not honored

MINOR. `templates/TICKET-TEMPLATE.md:36` states: "`y` is a zero-padded sequence within the sub-lane (`01`, `02`, ...)". Lane B / Lane C tickets use single-digit (`release work-B1.6`, `release work-C2.7`). Lane A also uses single-digit (`threat evidence item`).

**Proposed fix** (Wave 3):
- Either honor the zero-pad convention (`threat evidence item` -> `threat evidence item`, but `release work-B0.1` -> `release work-B0.01`, `release work-B1.6` -> `release work-B1.06`), OR amend `TICKET-TEMPLATE.md:36` to say "`.y` is an integer sequence; zero-padding optional but consistent within a sub-lane".

---

## 3. Cross-lane dependency graph

### 3.1 Lane C dependency expression style

See findings 2.2 above. BLOCKER for evidence-gate tooling.

### 3.2 W1 master finding: B2 fine-grained gate on Bar 3

OBSERVATION. The README `Trj4 wave-plan absorption` table (line 105-114) maps trj4 receipt v2 to release work-B2 and bilateral demo to release work-C1; the cross-lane dependency table (`EXECUTION-BOARD.md:84`) explicitly states "Bilateral receipts must mint as v2 under negotiated v2; the warn-and-downgrade path would silently weaken the demo." This propagates correctly to:

- `lane-c-demo/README.md:42-47` ("Receipt v2 fail-closed under negotiated v2... Demo proves v2 negotiated => v2 emitted").
- `lane-c-demo/planning docs:206-209` (release work-C3.3 "Receipt persistence ... Depends on: LB-RV2 (so v2 actually emits when negotiated)").

The propagation is healthy; the only loose end is the alias-vs-ID issue in 2.2.

### 3.3 Lane A and Lane B/C cross-coupling

OBSERVATION. The plans are correctly independent: Lane A does not block Lane B/C, Lane A does not consume Lane B/C output. `lane-a-floor/README.md:51-58` is explicit. `EXECUTION-BOARD.md:79` "no Lane A -> Lane B or Lane A -> Lane C dependency". Healthy.

### 3.4 Hidden Lane A vs Lane B coupling on `chio-anchor`

MAJOR. `OWNERS.toml:103` records that `crates/chio-anchor/` is in the `[overlaps]` table for lanes A, B, and C. Concretely:

- Lane A `mutation evidence item` (`planning docs:25`) drives mutation kill on `chio-anchor`.
- Lane A `Kani harness evidence` (`planning docs:97`) writes `crates/chio-anchor/src/kani_public_harnesses.rs`.
- Lane B `release work-B3.2` (`planning docs:42`) gates `crates/chio-anchor/src/batch.rs:227-235`.
- Lane C `release work-C3` consumes `crates/chio-anchor::Web3CheckpointStatement`.

If Lane A and Lane B both touch `chio-anchor` in the same wave, merge conflicts are inevitable. `OWNERS.toml:103` lists `["A", "B", "C"]` overlap but does not name a coordination owner. The Kickoff checklist line 38 demands "Path-overlap conflicts in `[overlaps]` have a coordination owner named". Today none is named.

**Proposed fix** (Wave 3):
- `OWNERS.toml:99-110` add an `[overlaps_owner]` table or expand `[overlaps]` to record `coordination_owner = "release owner"` (the `single_owner` per the manifest).
- `KICKOFF-CHECKLIST.md:38` make this an explicit gating checkbox: "[ ] `OWNERS.toml` `[overlaps]` rows that span multiple lanes carry a `coordination_owner` field."

### 3.5 `crates/chio-conformance/tests/` overlap

MINOR. `OWNERS.toml:104` lists overlap on `crates/chio-conformance/tests/` between A and B. Lane A's threat-coverage (release work-A2) does not strictly write under `chio-conformance/tests/`; it writes under `audits/evidence/threats/` and `tests/threats/`. Lane B writes three files under `chio-conformance/tests/`. The overlap is real for the test home conventions but not for code conflicts. Still, the `[overlaps]` row exists; coordination owner must be named.

**Proposed fix** (Wave 3): same as 3.4, plus consider tightening the overlap row to `["B"]` if `tests/threats/` is a separate path.

---

## 4. Ship-bar consistency

### 4.1 Three bars, three lane PLAN.md, three rows: clean

OBSERVATION. `lane-a-floor/README.md:31-34` claims Bar 1; `lane-b-wiring/README.md:15-19` claims Bar 2; `lane-c-demo/README.md:153-176` (acceptance) maps to Bar 3 in spirit (the language is "Lane C closes when..." rather than "Bar 3 closes when..."). The mapping is implicit but reasonable. Each lane PLAN/README has enough text that a reviewer can connect lane close to bar.

### 4.2 Bar 1 evidence count drift (20 vs 21 files)

MAJOR. The synthesis (line 79) and master `SHIP-BAR-TRACKER.md:23,27` and `KICKOFF-CHECKLIST.md:75` say "21" threat-evidence files. `lane-a-floor/README.md:23-25,124-134` correctly observes the actual file count is 20 (one per row in `spec/security/chio-threat-model.v1.json`) and absorbs an "if 21 confirmed by parent, becomes A2.21" assumption. The actual on-disk count (verified `ls audits/evidence/threats/ | wc -l`) is 20.

The master docs and lane plans disagree numerically. A reviewer reading SHIP-BAR-TRACKER will look for 21 files and find 20. The signal-block (`SHIP-BAR-TRACKER.md:27`) literally says "21 files; each with `caught >= 1`", which fails when 20 are produced.

**Proposed fix** (Wave 3):
- Update master docs to match disk reality:
  - `SHIP-BAR-TRACKER.md:23,25,27` change "21" -> "20".
  - `README.md:71` change "21".
  - `EXECUTION-BOARD.md:34` change "21" -> "20".
  - `KICKOFF-CHECKLIST.md:75` and the trj4-absorption note in `KICKOFF-CHECKLIST.md:66` is fine (TRJ4-040..049 is the trj4-side ticket count, not the file count).
  - `architecture/RISK-REGISTER.md:107,128,137` change "21" -> "20".
- If a 21st row is intentional (e.g. a future row pinned to add at release close), the synthesis must be re-opened (it is normative). The Lane A agent already documented this; the master docs need to follow.

### 4.3 Bar 2 line-range and trait-name drift

BLOCKER (master). The Lane B agent corrected:

- The receipt v2 downgrade is at `crates/chio-kernel/src/kernel/mod.rs:1574-1591` (function `kernel_receipt_version_for_remote`), NOT `:1148-1165` (which is the `KernelReceiptVersion::from_capabilities` resolver helper).
- The trait is `ToolServerConnection` at `crates/chio-kernel/src/runtime.rs:254`, NOT `ToolServer`.

The correction lives in `lane-b-wiring/receipt-v2-failclosed.md:36`, `lane-b-wiring/PLAN.md:94,106`, `lane-b-wiring/planning docs:32`, `architecture/ASYNC-KERNEL-MIGRATION.md:43`. The master docs still cite the old refs:

| File | Old ref | Line(s) |
|---|---|---|
| `EXECUTION-BOARD.md` | `mod.rs:1148-1165` | 52 |
| `EXECUTION-BOARD.md` | `async_trait \`ToolServer\`` | 80 |
| `SHIP-BAR-TRACKER.md` | `mod.rs:1148-1165` | 23, 40, 42 |
| `SCOPE-LOCK.md` | `mod.rs:1148-1165` and `async_trait \`ToolServer\`` | 26, 28, 54 |
| `README.md` | `mod.rs:1148-1165` and ``async_trait` on `ToolServer`` | 75, 108 |
| `TIMELINE.md` | `async_trait \`ToolServer\`` | 67 |
| `architecture/SPEC-TO-RUNTIME-MAP.md` | `mod.rs:1148-1165` | 38 |
| `templates/EVIDENCE-GATE.md` | `mod.rs:1148-1165` | 170 |
| `templates/CONFORMANCE-FIXTURE-PATTERN.md` | `mod.rs:1148-1165` (in worked-example diff) | 144, 246 |
| `lane-c-demo/README.md` | `mod.rs:1148-1165` | 43 |
| `lane-c-demo/architecture.md` | `mod.rs:1148-1165` | 155, 259 |
| `lane-c-demo/release-bar.md` | `mod.rs:1148-1165` | 183 |
| `lane-c-demo/planning docs` | `\`ToolServer\`` (LB-AT alias and release work-C1.4 scope text) | 13, 64 |
| `lane-c-demo/PLAN.md` | `\`ToolServer\`` | 63, 367 |

Bar 2's machine-readable signal (`SHIP-BAR-TRACKER.md:44`) names three test files; the test home is correct (`crates/chio-conformance/tests/`), but the underlying call-site reference inside the conformance test header comments will diverge from production unless this is fixed pre-execution.

`lane-b-wiring/receipt-v2-failclosed.md:36` is explicit: "The synthesis (line 31) cited the line range `mod.rs:1148-1165` as the downgrade location. That line range is actually the `KernelReceiptVersion::from_capabilities` resolver helper (peer-profile -> version mapping), which is correct on the spec side. The actual runtime downgrade-to-v1 lives at lines 1574-1591." This footnote MUST propagate.

**Proposed fix** (Wave 3, and this is the single most-load-bearing fix):
- Find-and-replace `mod.rs:1148-1165` with `mod.rs:1574-1591` (function `kernel_receipt_version_for_remote`) across master docs.
- Find-and-replace ``ToolServer\`` (when referring to the connection trait) with ``ToolServerConnection\`` across master docs.
- Add a one-line erratum block at the top of `debate/00-SYNTHESIS.md` (or in a separate `debate/00a-errata.md`) noting the line-range correction so the synthesis itself does not silently mutate.
- The synthesis text on lines 31, 38, 95, 105 is the source of the drift; it should be footnoted not edited (the synthesis is the contract; later corrections live in errata, not by overwriting the contract).

### 4.4 Lane C "close" without bar-mapping language

MINOR. `lane-c-demo/README.md:155-176` says "Lane C closes when..." with six conditions. The conditions match Bar 3 evidence in spirit but never explicitly say "Bar 3 reads DONE". A reviewer cross-referencing `SHIP-BAR-TRACKER.md:51-65` against the lane README has to do the mapping mentally.

**Proposed fix** (Wave 3, optional):
- `lane-c-demo/README.md` add a sentence in section "Acceptance": "When all six are met, `SHIP-BAR-TRACKER.md` Bar 3 transitions PARTIAL -> DONE; otherwise it stays PARTIAL with the missing condition called out in the per-week summary."

---

## 5. Evidence Gate compliance

### 5.1 Lane A: partial compliance

OBSERVATION. `lane-a-floor/planning docs:8-12` opens with: "Every ticket closes under the Lane A Evidence Gate trio (PLAN.md `Evidence Gate close bar`): enforced call site + spec/audit citation + signed evidence artifact." Each sub-lane carries a `close-bar artifact` row and an `anti-pattern guard`. The four-artifact rule (`templates/EVIDENCE-GATE.md:18-101`) asks for: enforced call site, spec MUST OR audit JSON, signed negative test, production-call-path exercise. Lane A maps to the Lane A variant in section 1.3 (audit JSON instead of spec MUST). The shape is consistent.

However, individual Lane A tickets do not carry the literal `Acceptance` sub-section the TICKET-TEMPLATE Section 2.2 prescribes. The lane-level "close-bar artifact" is sufficient for sub-lane gating but does not pass the `scripts/check-release work-evidence-gate.sh` per-ticket parser unless the parser is laxer than what `templates/TICKET-TEMPLATE.md:84-107` demands.

### 5.2 Lane B: best compliance, but ticket-level structure still informal

OBSERVATION. `lane-b-wiring/planning docs:9` "Acceptance includes the Evidence Gate close bar from `README.md`" plus per-ticket "Acceptance:" inline. Each release work-B1.x..B3.x ticket has an Acceptance line. The Acceptance lines do not follow the numbered five-row TICKET-TEMPLATE Section 2.1 format; they are prose. The intent is clear; the parser-friendliness is poor.

**Proposed fix** (Wave 3, optional but recommended for `scripts/check-release work-evidence-gate.sh` to function):
- Each Lane B ticket's Acceptance becomes the five-row block from `TICKET-TEMPLATE.md:65-82`.

### 5.3 Lane C: zero Evidence Gate references

MAJOR. `grep -c "Evidence Gate" lane-c-demo/planning docs` returns 0. `grep -c "TRJ4" lane-c-demo/planning docs` returns 0. The Evidence Gate is not invoked; the trj4 absorption is not back-referenced. This is a structural compliance gap  -  every Lane C ticket should at minimum cite its spec MUST line range and its negative-conformance test path (per `templates/CONFORMANCE-FIXTURE-PATTERN.md:38-51`). Some tickets cite spec sections (e.g. release work-C2.4 cites "spec section 7" implicitly via the verifier), but the Acceptance shape is not the four-artifact rule.

**Proposed fix** (Wave 3):
- `lane-c-demo/planning docs` introductory block: add the same paragraph Lane B uses ("Every C ticket closes under the Evidence Gate trio: enforced call site + spec MUST citation + signed negative conformance test that fails when wiring is removed.").
- Each release work-C* ticket's Acceptance row gains an explicit spec-MUST citation field and a negative-conformance test path field.
- The C2 sub-lane already has release work-C2.5 "Negative conformance fixture set"; the trj4-erratum failure mode is to land the structural code without the fixture pairing. The Acceptance row should make this explicit per ticket.

### 5.4 Sample audit of 5 tickets

Per the review prompt, sampling per lane:

| Ticket | Has Evidence-Gate-shaped acceptance? | Negative-conformance test cited? | Spec MUST cited? | Production-call-path exercise cited? |
|---|---|---|---|---|
| mutation evidence item (mutation kill chio-policy) | yes, prose | n/a Lane A | n/a Lane A | yes (mutation run) |
| threat evidence item (native_channel_replay) | yes, prose | yes (test rewrite + deny assertion) | n/a (audit JSON) | yes |
| release work-A4.4 (apalache-temporal required) | yes, prose | n/a (TLA+ proof) | n/a | yes (workflow run) |
| release work-B1.6 (b1 negative conformance fixture) | yes, prose; should be 5-row | yes (fixture path named) | yes (PROTOCOL.md 408-418) | yes (header-comment "fails when reverted") |
| release work-B2.5 (b2 negative conformance fixture) | yes, prose | yes (fixture path named) | yes (PROTOCOL.md 714-741) | yes |
| release work-B3.5 (b3 negative conformance fixture) | yes, prose | yes (fixture path named) | yes (PROTOCOL.md 982-991) | yes |
| release work-C1.2 (two-kernel handshake) | no | no | no | no |
| release work-C2.4 (17-step verifier) | yes, prose | yes (release work-C2.5 covers it) | implicit ("spec section 7") | yes |
| release work-C5.4 (disclosure envelope) | yes, prose | partial (round-trip test) | yes (spec section 8) | yes |
| release work-C6.5 (tag and ship) | yes, prose | n/a (operational) | n/a | n/a |

Lane C C1.x, C3.x, C4.x tickets are weakest; they are scaffolding-shaped and rely on aggregate close in C2.5 and C6.x.

---

## 6. Timeline conflicts

### 6.1 Lane A "weeks 1-8" ambiguity vs Lane A internal "5/6/7/8" flow

OBSERVATION. `TIMELINE.md:35-51` shows Lane A starting in W1 across all five sub-lanes. `lane-a-floor/README.md:64-79` lists per-week milestones; A1, A3, A5 (which is now Lean4) start at W1; A2 ramps W5; A4 starts W1. The flow is consistent within Lane A.

### 6.2 Lane C R4 mitigation contradicts the timeline

MAJOR. `architecture/RISK-REGISTER.md:163-164` mitigation says: "Lane C tickets are scheduled to START before Lane B closes, so demo smoke-tests run continuously against in-progress Lane B work." But `TIMELINE.md:71-79` and `EXECUTION-BOARD.md:91` both schedule Lane C unlock at end of week 4 (after B1/B2/B3 land), which is exactly when Lane B closes B-EG. The R4 mitigation is not implemented in the timeline.

The synthesis intent (Lane C as continuous forcing function for Lane B partial-enforcement detection) requires Lane C smoke fixtures to be operational while Lane B is mid-flight. Today's plan defers Lane C entirely until Lane B's three primitives land; this is exactly the trj4 pattern where the forcing function does not run continuously.

**Proposed fix** (Wave 3):
- Either:
  - (A) `TIMELINE.md` Lane C's C1 (architecture and scenario scaffolding) starts in W3 (week 3) so the smoke harness exists when Lane B B1.6/B2.5/B3.5 negative conformance fixtures land. Tickets release work-C1.1 (scaffold), release work-C1.2 (handshake), release work-C1.4 (refund tool) could start W3 in parallel with Lane B B1/B2/B3.
  - (B) `architecture/RISK-REGISTER.md:163-164` rewrites the mitigation to acknowledge Lane C does not run continuously and substitutes a different mitigation (e.g., "Lane B Evidence Gate review will hand-test against Lane C scenario scripts written in advance").
- Recommended: Option (A). It costs Lane C one engineer-week of W3 slack. Lane B's partial-enforcement findings would surface a week earlier.
- `lane-c-demo/README.md:131-134` already says "Lane C ships AFTER the three Lane B negative conformance fixtures exist" -- that contradicts R4 too. Clarify: scaffolding (C1.1, C1.2, C1.4) starts W3; full demo (C2-C6) waits for Lane B close.

### 6.3 Lane B "weeks 1-6" rather than "1-8"

OBSERVATION. Master docs (`README.md:60`, `EXECUTION-BOARD.md:13`) say Lane B duration is 6 weeks. `TIMELINE.md:60-65` shows Lane B B-EG landing at end of W6, and `TIMELINE.md:91-94` shows Bar 2 verification at W8. Lane B PLAN's `planning docs:46-51` "release work-B.CLOSE" is scheduled implicitly at W6. The two-week gap (W7-W8) is integration / ship-bar verification week, not new Lane B work. Healthy.

### 6.4 Critical path realism

OBSERVATION. The critical path `B0 -> {B1,B2,B3} -> C1 -> C2..C5 -> C6` totals ~8 weeks. The R1 risk callout (`RISK-REGISTER.md:43-50`) flags B0 as the highest-risk slip point. If the implementer enumeration (B0.1) shows >8 implementers (which is `lane-b-wiring/planning docs:11` already enumerates 11 production impls plus ~20 test impls = 31 total), R1 escalation criteria fire. The plan acknowledges this; the rollback in `ASYNC-KERNEL-MIGRATION.md:265-299` is documented. Acceptable.

---

## 7. trj4 wave-plan absorption

### 7.1 Master mapping is comprehensive

OBSERVATION. `README.md:99-114` table maps trj4 IDs to release work lanes. `KICKOFF-CHECKLIST.md:62-69` enumerates each row as a checkbox. `OWNERS.toml:45,71,96` lists `trj4_absorbed = [...]`. The aggregation is consistent across master docs.

### 7.2 Lane A absorption note short

MINOR. `lane-a-floor/README.md:10` says "TRJ4-010..014, TRJ4-015..018, and TRJ4-040..047" but master `SCOPE-LOCK.md:122` says "TRJ4-040..049". The Lane A absorption note is short by 2 trj4 IDs. The discrepancy is mechanical: Lane A internalized the actual file count (20) and back-extrapolated to TRJ4-040..047 (8 IDs), but the trj4 wave plan apparently runs to TRJ4-049 (10 IDs).

If trj4 IDs TRJ4-048 and TRJ4-049 reference threat rows that do not exist on disk (i.e. they were planning placeholders), the master docs may be the ones drifting from reality. This needs cross-checking against `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md`.

**Proposed fix** (Wave 3):
- Read `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md` (or the trj4 EXECUTION-BOARD) and resolve: are TRJ4-048 and TRJ4-049 real trj4 wave-plan tickets, and if so what threat rows do they cover?
- If TRJ4-040..049 = 10 IDs and 20 threat rows, some trj4 IDs cover multiple rows. Lane A planning docs enumerates 20 sub-tickets (A2.1..A2.20) which is correct; the IDs TRJ4-048/049 should land in OWNERS.toml `trj4_absorbed` (which they do today, line 45) and Lane A should reference the full range in its README.

### 7.3 Lane B back-references missing

MAJOR. `lane-b-wiring/planning docs` has 0 occurrences of `TRJ4`. The master `KICKOFF-CHECKLIST.md:67-69` says trj4 IDs "absorbed by **release work-B1**", "**release work-B2**", "**release work-B3**" but the lane tickets do not record per-trj4-ID absorption. If a trj4 close-bar audit asks "which release work ticket closed TRJ4-103?", the answer is "release work-B1.x for some x" but the specific x is not annotated.

**Proposed fix** (Wave 3):
- `lane-b-wiring/planning docs` add a "trj4-absorbed" column to each table row, mirroring `lane-a-floor/planning docs:155-158` style.
- Equivalent for `lane-c-demo/planning docs` if Lane C IDs absorb any trj4 work (currently `OWNERS.toml:96` says `trj4_absorbed = []` for Lane C, so no).

### 7.4 TRJ4 wave 0/1/4 explicit absorption

OBSERVATION. The synthesis says "Absorbs trj4 Wave 0 / Wave 1 / Wave 4" (00-SYNTHESIS.md:75). Master docs map waves to lanes. Wave 0 (preflight scripts, mutants infrastructure) ties to mutation evidence item and `scripts/release work-preflight.sh`. Wave 1 (substrate hardening) ties to A1-A4. Wave 4 (formal methods) ties to A3-A5/A6. Wave 6 (mobile attestation) is explicitly OUT-OF-SCOPE per `SCOPE-LOCK.md:88-94`. Coverage is reasonable.

If the trj4 wave plan has additional waves not absorbed (e.g. Wave 2, Wave 3, baseline, Wave 7+), those are presumably on-track in the trj4 wave plan and not pulled into release work. Confirm in Wave 3 by listing trj4 wave numbers and their resolution status.

---

## 8. Lane B agent line-range and trait-name corrections

This is the single biggest cluster of fixes. See section 4.3 above for the BLOCKER finding and full file list.

### 8.1 Why this matters for Bar 2

The conformance fixtures named in `SHIP-BAR-TRACKER.md:44` (`single_entry_verifier_no_bypass.rs`, `receipt_v2_fail_closed_under_negotiated_v2.rs`, `anchor_batch_async_only_with_public_witness.rs`) carry header-comment annotations per `templates/CONFORMANCE-FIXTURE-PATTERN.md:120-135`:

```
//! Enforced call site: crates/<crate>/src/<file>:<line>
```

If the master docs cite `:1148-1165` and the actual production hot path is at `:1574-1591`, a future reviewer running `scripts/check-release work-evidence-gate.sh` will see the test header citing `:1574-1591` and the spec evidence row citing `:1148-1165`, and the gate script will fail (or worse, pass on stale data because the cited line range now exists in some unrelated function).

### 8.2 Recommended fix sequencing

1. Patch master docs (master + architecture + templates) first.
2. Patch lane-c-demo/README.md, architecture.md, release-bar.md, PLAN.md, planning docs.
3. Add an erratum stub at `.planning/trajectory-5/debate/00a-errata.md` recording the synthesis-source-text correction without rewriting the synthesis.
4. Run `grep -rn "1148-1165\|ToolServer\b" .planning/trajectory-5/` and verify no stragglers (excluding `ToolServerConnection`, `ToolServerOutput`).

The list of specific files and lines is enumerated in section 4.3.

---

## 9. Lane C DSSE PAE escalation propagation

See section 1.4 (BLOCKER). The Option-A two-signature surface decision lives in Lane C deep-dive only. Master docs need:

- `architecture/SPEC-TO-RUNTIME-MAP.md` row.
- `SHIP-BAR-TRACKER.md` Bar 3 evidence row.
- `SCOPE-LOCK.md` in-scope sub-row.
- `architecture/RISK-REGISTER.md` R7.

### 9.1 Is this a Lane B item rather than Lane C?

OPEN QUESTION. The synthesis (line 122) says Lane C uses existing `crates/chio-federation/src/bilateral.rs`. If the DSSE PAE adapter is purely additive (a new module `bilateral_dsse.rs` next to `bilateral.rs`, no changes to `DualSignedReceipt::verify`), then Lane C ownership is correct. If the adapter requires Lane B kernel changes (e.g., the kernel emits both signatures during dispatch, making the dispatch path care about DSSE), then it belongs partly in Lane B.

`lane-c-demo/bilateral-cosign-flow.md:202-235` shows `build_envelope_from_dual_signed` taking `&Keypair` arguments  -  the kernel does not need to know about DSSE. Verification (`verify_envelope`, `bilateral-cosign-flow.md:237-272`) takes `&PeerPinSet` and a receipt store. These are demo-side; no kernel hot-path mutation is required.

**Conclusion**: Lane C can own the DSSE PAE adapter without crossing into Lane B. The propagation fix is purely doc-level (master docs need to acknowledge the two-signature design), not a scope shift.

---

## 10. Forcing-function integrity (Lane C as continuous forcer)

See section 6.2 (MAJOR). `architecture/RISK-REGISTER.md:163-164` claims continuous Lane C smoke against in-progress Lane B; the timeline does not implement this. The fix is either to ship Lane C scaffolding earlier (recommended) or to re-state the mitigation honestly.

If Lane C does not run during Lane B development, the "If Lane C breaks, Lanes A and B aren't real either" framing (synthesis line 175) is not operationalized. Lane C only runs once at the end; if it breaks, there is no time-cushion for Lane B to fix.

### 10.1 Proposed plan-level patches

- `lane-c-demo/README.md:131-134`: rewrite the "Lane C ships AFTER" sentence as "Lane C scaffolding (C1.1, C1.2, C1.4) lands in week 3 alongside Lane B; full demo runs in weeks 5-7 once Lane B B1.6 / B2.5 / B3.5 negative conformance fixtures land. Lane C smoke runs continuously from week 3 onward against the in-progress Lane B work; partial-enforcement findings have at least 2 weeks to surface and be fixed."
- `architecture/RISK-REGISTER.md:163-164`: reinforce the mitigation with a concrete artifact ("a CI workflow `chio-demo-smoke-preview.yml` runs Lane C scenarios in advisory mode starting W3").
- `EXECUTION-BOARD.md` cross-lane dependency table: change `release work-C1` -> `release work-B1, release work-B2, release work-B3` to `release work-C1.1, C1.2, C1.4` -> none (W3 start) and `release work-C1.3, C2.x, C3.x, ...` -> `release work-B1.6, B2.5, B3.5`. The R4 risk's mitigation effect now matches the dep graph.

---

## 11. Other minor findings

### 11.1 Lane A README assumption note location

MINOR. `lane-a-floor/README.md:124-142` notes assumptions about file count (20 vs 21) and TLA+ property names. These are valuable context. Wave 3 should propagate the file-count assumption to master docs (see 4.2) and confirm the TLA+ property assumption with `formal/tla/RevocationPropagation.tla` content.

### 11.2 OWNERS.toml conflict-resolution

MINOR. `OWNERS.toml:103-110` `[overlaps]` table lacks coordination owners. See 3.4. Worth a Wave 3 patch independent of any other.

### 11.3 KICKOFF-CHECKLIST checkbox count

OBSERVATION. The checklist has many checkboxes but no overall "n/m" tally. Trj5 closeout should add a script that reads the checklist and reports "X of Y prerequisites met" so kickoff readiness is visible.

### 11.4 README banner reproducibility

OBSERVATION. `lane-a-floor/planning docs:28` (mutation evidence item) says "Verify the banner update is reproducible: re-running the workflow on the same data produces an identical line." This is a strong anti-drift guard; commend the agent for it. Master docs do not have an equivalent reproducibility check for the Bar 1 signal; consider adding one.

### 11.5 TICKET-TEMPLATE worked example uses old line ranges

MINOR. `templates/TICKET-TEMPLATE.md:140-171` worked example `release work-B1.03` cites `crates/chio-kernel/src/kernel/mod.rs:<line-after-patch>` (correct, generic) but the surrounding text references "lines 408-418 (post-amend)" which is healthy. No drift.

### 11.6 EVIDENCE-GATE.md anti-pattern 2.4 cites old line range

MINOR. `templates/EVIDENCE-GATE.md:170` says "(`crates/chio-kernel/src/kernel/mod.rs:1148-1165`)" in the `Receipt v2 dual-mint emits "a structured warning..."` example. Correct citation per Lane B agent: `:1574-1591`. See section 4.3 file list.

### 11.7 Conformance fixture pattern revert diff is illustrative

MINOR. `templates/CONFORMANCE-FIXTURE-PATTERN.md:140-150` shows a diff at `@@ -1148,1165 +1148,1148 @@` which is purely illustrative. Should still be updated to the corrected line range when the master docs are corrected.

---

## Open questions for the release work owner

1. **Synthesis-source correction policy.** The synthesis text on lines 31, 38, 95, 105 cites `:1148-1165` and `ToolServer`. These are wrong as of the Lane B agent's verification. Do you want the synthesis edited (which means re-opening the contract), or footnoted via an errata file? Recommendation: footnote.
2. **release work-A5 / equivalence-tests.** Lane A swapped release work-A5 (equivalence) for release work-A6 (Lean) and dropped TRJ4-019. Do you want the equivalence work re-instated in release work or moved to trj6? If trj6, SCOPE-LOCK and master docs must reflect it.
3. **Threat-evidence file count (20 vs 21).** The actual file count is 20. Master docs say 21. Update master to 20, or commit to creating a 21st row (and which threat does it cover)?
4. **Continuous Lane C run.** R4 mitigation says continuous; timeline says deferred. Do you want to ship Lane C C1 scaffolding starting W3 (recommended) or to weaken R4's mitigation?
5. **Ticket-ID convention.** TICKET-TEMPLATE says `.E` per sub-lane; EXECUTION-BOARD says `B-EG`; lane-b/tickets says `B.CLOSE`. Pick one. Recommended: TICKET-TEMPLATE wins.
6. **Evidence Gate compliance for Lane C.** Lane C tickets do not currently invoke the Evidence Gate. Wave 3 will add the framing. Confirm acceptable.
7. **DSSE Option-A surfacing.** The two-signature decision needs to live in master docs (SPEC-TO-RUNTIME-MAP, SHIP-BAR-TRACKER, SCOPE-LOCK, RISK-REGISTER R7). Approve the propagation?
8. **OWNERS.toml overlap coordination.** No `coordination_owner` named for `chio-anchor` overlap. Default to `release owner` (single_owner) for release work?

---

## Verdict

**APPROVED-WITH-FIXES.** The release work plan shape matches the synthesis. The defects are mechanical and addressable in Wave 3 without re-opening the synthesis (subject to question 1's answer).

Required Wave 3 fixes (must land before kickoff):

1. (BLOCKER) Line-range and trait-name correction across master docs and Lane C deep-dive (section 4.3, section 8).
2. (BLOCKER, on Lane C internal compliance) Lane C tickets gain Evidence Gate framing and explicit spec-MUST citations (section 5.3).
3. (BLOCKER, on Lane C internal compliance) Lane C cross-lane deps switch from aliases to literal ticket IDs (section 2.2).
4. (MAJOR) DSSE Option-A propagation to master docs (section 1.4, section 9).
5. (MAJOR) release work-A5 equivalence-tests sub-lane re-instated OR explicit deferral to trj6 with synthesis-update note (section 2.3).
6. (MAJOR) Threat-evidence file count master/Lane A reconciliation (section 4.2).
7. (MAJOR) Ticket-ID Evidence-Gate suffix unified (section 2.1).
8. (MAJOR) R4 / continuous Lane C operationalized (section 6.2, section 10).
9. (MAJOR) `OWNERS.toml` overlap rows gain coordination owners (section 3.4).
10. (MAJOR) Lane B and Lane C tickets back-reference trj4 IDs (section 7.3).

Recommended Wave 3 fixes (nice to have, not gating):

- Lane B/C ticket Acceptance blocks become 5-row TICKET-TEMPLATE format (section 5.2).
- Reproducibility check for Bar 1 signal and Bar 3 fixture tarball (section 11.4).
- Zero-pad convention either honored or relaxed in TICKET-TEMPLATE (section 2.5).

Trj5 stays open until all BLOCKER fixes land. MAJOR fixes should land before week 1; otherwise they will be discovered as drift during execution, repeating the trj4 pattern.

---

## File-touch summary for Wave 3

| File | Findings |
|---|---|
| `debate/00-SYNTHESIS.md` | (read-only contract; errata file proposed) |
| `debate/00a-errata.md` (new) | line-range + trait-name corrections (8.2) |
| `README.md` | lines 71, 75, 108: line-range + trait-name + threat-count |
| `EXECUTION-BOARD.md` | lines 34, 52, 54, 80, 91, 124: line-range + trait-name + threat-count + B-EG rename + critical path |
| `SHIP-BAR-TRACKER.md` | lines 23, 25, 27, 40, 42: line-range + threat-count + Bar 3 DSSE evidence |
| `SCOPE-LOCK.md` | lines 26, 28, 36-42, 54, 122: line-range + trait-name + DSSE in-scope sub-row + Lane A absorption |
| `TIMELINE.md` | line 67: trait-name; lines 71-79: Lane C scaffolding W3 start |
| `KICKOFF-CHECKLIST.md` | line 38: overlap coordination owner; line 75: threat-count |
| `OWNERS.toml` | lines 99-110: coordination owners |
| `templates/EVIDENCE-GATE.md` | line 170: line-range correction |
| `templates/CONFORMANCE-FIXTURE-PATTERN.md` | lines 144, 246: line-range correction in worked example |
| `templates/TICKET-TEMPLATE.md` | (review zero-pad convention; consider amending) |
| `architecture/SPEC-TO-RUNTIME-MAP.md` | line 38: line-range correction; section 8 add DSSE Option-A row |
| `architecture/RISK-REGISTER.md` | lines 107, 128, 137: threat-count; lines 163-164: R4 mitigation; new R7 for DSSE Option-B |
| `architecture/ASYNC-KERNEL-MIGRATION.md` | (already correct on `ToolServerConnection`; no changes) |
| `lane-a-floor/README.md` | line 10: TRJ4-040..049; lines 38-44: add equivalence sub-lane; lines 124-134: assumption propagated to master |
| `lane-a-floor/planning docs` | new sub-lane release work-A5 (equivalence) inserted; renumber Lean to A6 |
| `lane-b-wiring/planning docs` | back-reference trj4 IDs; rename `release work-B.CLOSE` -> `release work-B-EG`; format Acceptance as 5-row |
| `lane-c-demo/README.md` | line 43: line-range correction; section "Lane C ships AFTER" rewritten for continuous run |
| `lane-c-demo/architecture.md` | lines 155, 259: line-range correction |
| `lane-c-demo/release-bar.md` | line 183: line-range correction |
| `lane-c-demo/PLAN.md` | lines 63, 367: trait-name correction |
| `lane-c-demo/planning docs` | dep aliases -> literal IDs; Evidence Gate framing added; back-reference trj4 IDs |
| `lane-c-demo/bilateral-cosign-flow.md` | (already correct internally; no changes) |

## Appendix A: Diff-shaped patches for the BLOCKER fixes

### A.1 Receipt-v2 line range correction

The single most-load-bearing patch. Applied across master docs, architecture docs, templates, and Lane C deep-dive. The corrected reference is:

- **OLD**: `crates/chio-kernel/src/kernel/mod.rs:1148-1165` (this is `KernelReceiptVersion::from_capabilities`, a peer-profile resolver, not the runtime downgrade).
- **NEW**: `crates/chio-kernel/src/kernel/mod.rs:1574-1591` (function `kernel_receipt_version_for_remote`, the actual warn-and-downgrade site).

Sample patch for `EXECUTION-BOARD.md:52`:

```diff
-| release work-B2 | **Receipt v2 fail-closed under negotiated v2**: replace warn-and-downgrade at `chio-kernel/src/kernel/mod.rs:1148-1165` with a hard reject when negotiation indicated `chio.capability.v2`. PROTOCOL.md section 6 lines 714-741 changes "falls back" -> "fails closed". Signed negative conformance test asserts the hard-reject path. | protocol | M | release work-B0 | TRJ4-120..131 + T1.2.E |
+| release work-B2 | **Receipt v2 fail-closed under negotiated v2**: replace warn-and-downgrade in `kernel_receipt_version_for_remote` at `chio-kernel/src/kernel/mod.rs:1574-1591` with a hard reject when negotiation indicated `chio.capability.v2`. PROTOCOL.md section 6 lines 714-741 changes "falls back" -> "fails closed". Signed negative conformance test asserts the hard-reject path. (Note: synthesis line 31 cited `:1148-1165` which is the resolver helper; the runtime downgrade is at `:1574-1591`.) | protocol | M | release work-B0 | TRJ4-120..131 + T1.2.E |
```

Same shape for: `SHIP-BAR-TRACKER.md:23,25,40,42`, `SCOPE-LOCK.md:28`, `README.md:75`, `architecture/SPEC-TO-RUNTIME-MAP.md:38`, `templates/EVIDENCE-GATE.md:170`, `templates/CONFORMANCE-FIXTURE-PATTERN.md:144,246`, `lane-c-demo/README.md:43`, `lane-c-demo/architecture.md:155,259`, `lane-c-demo/release-bar.md:183`.

For `templates/CONFORMANCE-FIXTURE-PATTERN.md:140-150` worked example diff:

```diff
-@@ -1148,1165 +1148,1148 @@
-                if peer_features.accepts_receipt_v2 {
+@@ -1574,1591 +1574,1574 @@
+                if expects_v2 && !peer_pinned_fresh {
                     return Err(KernelError::ReceiptVersionMismatch { ... });
                 }
+                // Reverted: warn-and-downgrade restored.
                 tracing::warn!("receipt v1 minted under v2 negotiation");
+                return KernelReceiptVersion::V1Legacy;
```

### A.2 `ToolServer` -> `ToolServerConnection` correction

Sample patch for `EXECUTION-BOARD.md:50,80`:

```diff
-| release work-B0 | **Architectural prerequisite**: convert `ToolServer` trait to `async_trait`; collapse the dispatch sync-helper hop in `chio-kernel/src/kernel/mod.rs:6402`. Smallest decomposition cut that unblocks hot-path wiring; chio-cli trust-control extraction and gravity-well surgery stay out of release work. | kernel | L | none | (decomposition advocate prerequisite) |
+| release work-B0 | **Architectural prerequisite**: convert `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254` to `async_trait`; collapse the dispatch sync-helper hop in `chio-kernel/src/kernel/mod.rs:6402-6442`. Smallest decomposition cut that unblocks hot-path wiring; chio-cli trust-control extraction and gravity-well surgery stay out of release work. | kernel | L | none | (decomposition advocate prerequisite) |
```

```diff
-| release work-B0 | release work-B1 | hard | Single-entry verifier needs `async_trait` `ToolServer` to wire without sync-hop bouncing. |
+| release work-B0 | release work-B1 | hard | Single-entry verifier needs `async_trait` on `ToolServerConnection` to wire without sync-hop bouncing. |
```

Same shape for: `SCOPE-LOCK.md:26,54`, `README.md:108`, `TIMELINE.md:67`, `lane-c-demo/PLAN.md:63,367`, `lane-c-demo/planning docs:13,64` (the LB-AT alias gloss and the C1.4 scope text).

### A.3 DSSE Option-A surfacing in master docs

New row in `architecture/SPEC-TO-RUNTIME-MAP.md` section 8:

```diff
 | Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
 |---|---|---|---|---|
 | `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6 (TBD-from-W1: lines) | "DualSignedReceipt MUST carry both signers' attestations" | `crates/chio-federation/src/bilateral.rs::CoSigningBody`, `DualSignedReceipt` | enforced (existing primitive) | release work-C1.E asserts the demo exercises this |
 | same | "cross-org dispatch MUST not allow single-signer fast path" | TBD-from-W1 | structural-only | release work-C1.E |
+| `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6 lines 338-343 | "DSSE envelope signed over PAE bytes of canonical Statement" | `crates/chio-federation/src/bilateral_dsse.rs` (new module per `lane-c-demo/bilateral-cosign-flow.md:202`) | not-yet-enforced; Option-A two-signature design | release work-C2.3, release work-C2.4 |
+| same | "two-signature surface: existing CoSigningBody Ed25519 + new DSSE PAE Ed25519" | both signatures share `Keypair`; existing `DualSignedReceipt::verify` unchanged | bounded by Option-A choice | release work-C2.7 |
```

New row in `SHIP-BAR-TRACKER.md:59` Bar 3 evidence:

```diff
-| **Evidence required** | (1) `examples/bounded-chiodome/` exists with a `Makefile` or `cargo run --example` recipe ... (8) Honest release tag `v0.1.0-bounded-chiodome` recorded in `releases.toml` `[trajectory_5]`. |
+| **Evidence required** | (1) `examples/bounded-chiodome/` exists with a `Makefile` or `cargo run --example` recipe ... (8) Honest release tag `v0.1.0-bounded-chiodome` recorded in `releases.toml` `[trajectory_5]`. (9) Bilateral DSSE adapter at `crates/chio-federation/src/bilateral_dsse.rs` produces an envelope whose two signatures (existing `CoSigningBody`-scoped Ed25519 and new DSSE PAE Ed25519) verify independently; existing `DualSignedReceipt::verify` continues to accept the legacy preimage; the demo emits both surfaces (Option A per `lane-c-demo/bilateral-cosign-flow.md:77-110`). |
```

New row in `SCOPE-LOCK.md:36-42` Lane C in-scope sub-row:

```diff
 | Two-kernel cross-org bilateral cosigned invocation using existing `crates/chio-federation/src/bilateral.rs`. | federation | release work-C1 |
+| DSSE PAE adapter co-existing with `CoSigningBody`-scoped Ed25519 (Option A). Adds new module `crates/chio-federation/src/bilateral_dsse.rs`; does not replace existing signing surface. | federation | release work-C2.1, release work-C2.3, release work-C2.4, release work-C2.7 |
```

New R7 in `architecture/RISK-REGISTER.md`:

```
## R7: Spec WG rejects Option-A two-signature design for bilateral DSSE

| Field | Value |
|---|---|
| Probability | low (15%) |
| Impact | high - Lane C scope expands materially |
| Owner-class | demo-eng + federation-eng |
| Lane | C2 |

**Description**: Lane C ships an Option-A two-signature surface (existing
`CoSigningBody`-scoped Ed25519 plus new DSSE PAE Ed25519). If the
`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` working group rejects this
during review (e.g. they want Option B: replace the signing surface so a
single canonical preimage exists), Lane C scope expands to include
migrating every existing fixture and verifier.

**Mitigation**:
- Lane C ships under bounded-claim discipline: the release notes for
  `v0.1.0-bounded-chiodome` say "Option A; Option B deferred to trj6
  pending WG resolution".
- The DSSE adapter is purely additive; existing `DualSignedReceipt::verify`
  is unchanged. If WG demands Option B, only the adapter and the demo
  fixtures rebake; production verifiers do not.

**Escalation criteria**:
- WG signal that Option B is required before release close.
- A downstream consumer (chio-tower, chio-cpp-kernel-ffi) cannot
  interoperate with Option A.

If escalated, Wave 2 reopens the synthesis to either include Option B
in release work (effort ~M-L) or to bound-claim Lane C as Option-A only and
document Option B as trj6.
```

### A.4 Lane A equivalence-tests sub-lane re-instate

New `lane-a-floor/planning docs` sub-lane `release work-A5` (after renaming current A5 -> A6):

```
## Sub-lane A5 - chio-equivalence-tests proptest hosted-vs-portable

| Ticket | Title | Lane | Effort | Depends-on |
|---|---|---|---|---|
| release work-A5.1 | Configure `chio-equivalence-tests` proptest harness for 10k cases per PR + 1M cases nightly. Files touched: `crates/chio-equivalence-tests/proptest-regressions.txt`, `crates/chio-equivalence-tests/Cargo.toml`. | A | M | - |
| release work-A5.2 | Capture two consecutive nightly green runs with zero divergence between hosted and portable kernels. Files touched: `audits/evidence/equivalence/<date>.json`. | A | S | release work-A5.1 |
| release work-A5.3 | Add `audits/evidence/equivalence/banner.json` summarizing run-to-run divergence count. Banner cites the two run URLs from A5.2. | A | S | release work-A5.2 |

**A5 close-bar artifact**: two green nightly proptest runs; equivalence
banner JSON; release-audit row.

**A5 anti-pattern guard**: a divergence count of zero must be observed,
not asserted. The banner is recomputed from the nightly artifact.

**Trj4 absorbed**: TRJ4-019.
```

The current Lane A `release work-A5` (Lean) becomes `release work-A6`; `planning docs:131-145` ticket IDs renumber A5.1..A5.4 -> A6.1..A6.4.

### A.5 Lane C ticket-format Evidence Gate framing

Sample patch for `lane-c-demo/planning docs:1-15` introductory block:

```diff
 # Lane C - Tickets

 Concrete tickets `release work-C1.x..C6.x`. Each entry has title, scope, files
 touched, effort (S/M/L), depends-on (cross-lane deps explicit),
 acceptance.

+Every ticket closes under the release work Evidence Gate trio (per
+`templates/EVIDENCE-GATE.md`): enforced call site + spec MUST citation +
+signed negative conformance test that fails when wiring is removed.
+Cross-lane dependencies cite literal Lane B ticket IDs (`release work-B0.5`,
+`release work-B1.6`, `release work-B2.5`, `release work-B3.5`), not aliases.
+
 Effort: S = under 1 day; M = 1-3 days; L = 3-6 days.

 Cross-lane dependencies:
-- `LB-CAP` = Lane B single-entry capability verifier
-- `LB-RV2` = Lane B receipt-v2 hot-path fail-closed
-- `LB-AB`  = Lane B anchor-batch async-only when public witness required
-- `LB-AT`  = Lane B `ToolServer` -> `async_trait` migration
+- `release work-B0.5` = Lane B0 dispatch-hop collapse (gating artifact for `async_trait` migration)
+- `release work-B1.6` = Lane B1 negative conformance fixture (gating artifact for single-entry verifier)
+- `release work-B2.5` = Lane B2 negative conformance fixture (gating artifact for receipt v2 fail-closed)
+- `release work-B3.5` = Lane B3 negative conformance fixture (gating artifact for anchor-batch async-only)
```

Per-C-ticket dep changes: release work-C1.2 `LB-AT` -> `release work-B0.5`; release work-C1.4 `LB-AT` -> `release work-B0.5`; release work-C2.4 `LB-CAP` -> `release work-B1.6`; release work-C3.3 `LB-RV2` -> `release work-B2.5`; release work-C4.2 `LB-AB` -> `release work-B3.5`.

### A.6 OWNERS.toml coordination owner

```diff
 [overlaps]
-"crates/chio-kernel/src/kernel/mod.rs" = ["B"]
-"crates/chio-anchor/" = ["A", "B", "C"]
-"crates/chio-conformance/tests/" = ["A", "B"]
-"crates/chio-federation/" = ["B", "C"]
-"spec/PROTOCOL.md" = ["B"]
-"spec/registries/" = ["A", "B"]
-"audits/evidence/" = ["A"]
-"formal/" = ["A"]
-".planning/trajectory-5/" = ["A", "B", "C"]
+"crates/chio-kernel/src/kernel/mod.rs" = { lanes = ["B"], coordination_owner = "release owner" }
+"crates/chio-anchor/" = { lanes = ["A", "B", "C"], coordination_owner = "release owner" }
+"crates/chio-conformance/tests/" = { lanes = ["A", "B"], coordination_owner = "release owner" }
+"crates/chio-federation/" = { lanes = ["B", "C"], coordination_owner = "release owner" }
+"spec/PROTOCOL.md" = { lanes = ["B"], coordination_owner = "release owner" }
+"spec/registries/" = { lanes = ["A", "B"], coordination_owner = "release owner" }
+"audits/evidence/" = { lanes = ["A"], coordination_owner = "release owner" }
+"formal/" = { lanes = ["A"], coordination_owner = "release owner" }
+".planning/trajectory-5/" = { lanes = ["A", "B", "C"], coordination_owner = "release owner" }
```

(If TOML inline-table mode is undesirable, alternative is `[overlaps_owner]` table keyed by the same path.)

---

## Appendix B: Validation script suggestions for Wave 3

Wave 3 fix agents should add the following gates to `scripts/release work-preflight.sh` so future drift is caught at PR time:

1. **No old line range**: `grep -rn "1148-1165" .planning/trajectory-5/ && exit 1` (after corrections land).
2. **No bare `ToolServer\b`** outside debate/ archives: `grep -rn "ToolServer\b" .planning/trajectory-5/ | grep -v "ToolServerConnection\|ToolServerOutput\|debate/"` returns zero.
3. **Ticket-ID convention**: `grep -hoE "release work-[ABC]\.[A-Z]+" .planning/trajectory-5/lane-*-*/planning docs` returns zero (no `release work-B.CLOSE`-style tags).
4. **Threat-evidence count**: `audits/evidence/threats/*.json` count matches the master-doc number.
5. **Cross-lane dep aliases**: `grep -E "LB-CAP|LB-RV2|LB-AB|LB-AT" .planning/trajectory-5/lane-c-demo/planning docs` returns zero (after correction).
6. **Spec MUST citation per Lane B/C ticket**: each ticket's Acceptance carries `Spec MUST:` or `Audit JSON:`.
7. **Trj4 back-reference per Lane**: each lane planning docs carries at least one `TRJ4-` reference (assuming at least one row absorbs trj4 work).

---

## Appendix C: Summary of lines-of-evidence per finding

| Finding | Severity | Files affected | Net diff |
|---|---|---|---|
| 4.3 / 8 line-range and trait-name drift | BLOCKER | 14 files | ~40 lines |
| 1.4 / 9 DSSE Option-A propagation | BLOCKER | 4 master docs | ~30 lines |
| 5.3 Lane C zero Evidence Gate | BLOCKER | 1 file | ~50 lines (intro + per-ticket) |
| 2.2 Lane C dep aliases | BLOCKER | 1 file | ~20 lines |
| 1.3 Lane C5 spec-ratification risk | MAJOR | 2 files | ~20 lines |
| 2.1 Evidence-Gate suffix collision | MAJOR | 3 files | ~10 lines |
| 2.3 Lane A swapped sub-lane numbering | MAJOR | 2 files | ~50 lines (new sub-lane) |
| 4.2 threat-evidence file count drift | MAJOR | 5 files | ~10 lines |
| 6.2 / 10 R4 vs timeline | MAJOR | 3 files | ~20 lines |
| 3.4 OWNERS.toml overlap coordinator | MAJOR | 1 file | ~10 lines |
| 7.3 Lane B/C trj4 back-references | MAJOR | 2 files | ~30 lines |
| 2.4 release work-A0 unenumerated | MINOR | 2 files | ~5 lines |
| 2.5 Zero-pad convention | MINOR | 1 file (template) | ~3 lines |
| 5.2 Lane B Acceptance prose | MINOR | 1 file | ~50 lines (refactor) |
| 4.4 Lane C "close" bar-mapping | MINOR | 1 file | ~3 lines |
| 7.2 Lane A absorption short | MINOR | 1 file | ~3 lines |
| 11.6 EVIDENCE-GATE anti-pattern 2.4 | MINOR | 1 file | ~2 lines (subsumed by 4.3) |
| 11.7 CONFORMANCE-FIXTURE-PATTERN diff | MINOR | 1 file | ~5 lines (subsumed by 4.3) |

Total estimated Wave 3 churn: ~360 lines across ~22 files.

End of R1 cross-lane review.
