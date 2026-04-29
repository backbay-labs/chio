# trajectory-2 authoring changelog

A running record of trajectory-2 planning artifact production, organized
by review round. Each round's entries note who landed what, what was
caught, and what remains for the next round (or for execution).

## 2026-04-29 Round 0: scaffolding (this conversation)

Created `.planning/trajectory-2/`, the empty milestone-directory tree, and
the four cross-cutting seed docs:

- `README.md` (milestone roster + cross-doc invariants)
- `STYLE.md` (authoring contract)
- `EXECUTION-STATE.json` (seed state)
- `tickets/schema.json` (extended `agent_role` enum: added `dx-rust`,
  `lsp-rust`, `quality-rust`, `crypto-rust`, `delegate-rust`, `arena-rust`,
  `econ-rust`, `framework-ts`, `lineage-rust`, `formal-lean`)

## 2026-04-29 Round 1: ten parallel milestone agents

Ten agents wrote the per-milestone narratives + per-phase ticket files in
parallel. Output: 10 narratives (148-539 lines each) + 60 phase YAMLs
totalling 318 tickets, 411.75 effort-days.

## 2026-04-29 Round 2: review/fix/continue (4 reviewers + 2 writers)

Six agents in parallel:

- **A1 mechanical:** zero fixes needed. Manifest regenerated.
- **A2 STYLE compliance:** confirmed all eleven STYLE.md sections present in all
  ten narratives. Re-authored `05-adversarial-escape-threat-model.md` from 148
  to 173 lines (~3,550 words; highest of any narrative).
- **A3 cross-milestone consistency:** caught and fixed M09 conflating
  trajectory-1 M05 (async kernel) with trajectory-2 M05 (adversarial). Plus 5
  other reconciliations: `CanonicalBytes` consumer-list mismatch, threat-model
  registry overstated as M04-consumer, D16 ticket-encoding gap, freeze ordering
  ticket ids, M08 corpus producer/consumer claim.
- **A4 scope-creep audit:** zero tickets removed. Tightened "Out (and why)"
  lists across M01/M02/M03/M04/M07. Wrote `SCOPE-CREEP-AMBIGUOUS.md` for 3
  ambiguous items.
- **B1 (AUTONOMOUS-PROMPT + COLD-READER-NOTES):** 625 + 514 lines. Surfaced
  one BLOCKER + 32 NEEDS-CLARIFY + 22 NICE-TO-HAVE.
- **B2 (CONTINUE-PROMPT + HANDOFF-PROMPT):** 397 + 393 lines. Template
  shapes mirror trajectory-1's prompts.

Plus the synthesizing pass: wrote `EXECUTION-BOARD.md` (278 lines),
`OWNERS.toml` (211 lines), `freezes.yml` (118 lines), `decisions.yml`
(369 lines, D01..D24).

## 2026-04-29 Round 3: triage findings + continue writing (4 fix + 4 write)

Eight agents in parallel:

- **F1 triage M01-M03:** 15 findings processed (12 applied, 1 deferred,
  2 addressed, 0 disagreed). Resolved cross-cutting BLOCKER (Domain enum
  extension story) by seeding M01.P1.T2 with eighteen domains up front
  (10 core + 8 reserved for downstream). Added new ticket M03.P0.T5
  (fips204 vs ml-dsa ecosystem re-confirmation). Surfaced D07 SDK-matrix
  ownership gap and pending D25 reference.
- **F2 triage M04-M06:** 15 findings processed (12 applied, 2 deferred,
  1 partial). M05 success criterion tightened from "25 escape classes"
  to "8" matching ticket reality. Federation peers in M04 pinned to N=3.
  M06 OTEL counter renamed `signing_queue_drop_total` -> `signing_queue_block_total`
  to distinguish block-vs-drop semantics.
- **F3 triage M07-M08:** 12 findings processed (6 applied, 3 appended,
  1 deferred, 0 disagreed). Resolved LangChain ambiguity (in-scope per D18 as a
  framework template, distinct from the cut `chio-langchain` SDK adapter).
  Surfaced D07 / SDK-matrix ownership question and wrote
  `RECONCILE-NEEDED.md` enumerating three resolution paths (M07.P6, M11
  pencil, or D07 re-scope).
- **F4 triage M09-M10 + cross-cutting + ambiguous:** 16 findings
  processed (10 applied, 5 appended, 0 deferred). Added **D25** (Domain
  enum eighteen-variant seed, `#[non_exhaustive]`) and **D26**
  (transitive activation of `chio-mercury`, `chio-mercury-core`,
  `chio-anchor` via `chio-settle` import + lineage anchor pin, avoiding
  a heavier P6 phase). Reconciled M10 `weights_hash_spoof` via a new
  `coverage_state` enum {covered, partial, pending} on the M05 schema.
  Resolved SCOPE-CREEP-AMBIGUOUS item 3 (M02 canonical for Miri).
- **W1 CI stubs + helper scripts:** 14 files, 1090 lines. Nine workflow
  stubs at `ci-stubs/` (mutation-coverage, verdict-matrix,
  threat-model-coverage, adversarial-suite, wasm-guard-escape,
  dhat-allocations, cold-start-budget, lean-build, apalache-delegation)
  plus README. Four helper scripts at `scripts/` (regen-manifest,
  validate-manifest, preflight-trajectory-2, install-orchestrator-tools).
- **W2 per-milestone READMEs:** 10 files, 52-59 lines each. Caught the
  M03 ticket count drift (31 -> 32) introduced by F1's
  `M03.P0.T5` addition; recorded the actual count in the README so it
  tracked the YAML.
- **W3 audit doc templates:** 4 files, 893 lines totalling 297 `<fill>`
  markers. One template per trust-boundary milestone (M03, M04, M05,
  M10) pre-filling the trust-boundary attestation scaffold.
- **W4 wave-opener strategy:** 1 file, 623 lines, 16 paste-ready
  commands. Caught two operational gaps: (a) M04 P3 has overlapping
  freezes (`m04-revocation-oracle-pivot` ends at P3.T5;
  `m04-delegation-pivot` starts at P3.T1) so the freeze guard workflow
  must union both rows; (b) the trajectory-1 `regen-codeowners.sh` is
  hard-coded to trajectory-1's OWNERS.toml so it needs a dual-trajectory
  extension before pre-flight item 2.4 can land.

### Synthesizing pass (this conversation)

- Manifest regenerated to 319 tickets / 412.25 effort-days (+1 ticket
  for `M03.P0.T5`). Manifest now 8,191 lines.
- Updated `EXECUTION-BOARD.md` provenance table (M03 31 -> 32 tickets,
  39.50 -> 40.00 days; total 318 -> 319, 411.75 -> 412.25). Updated
  the Wave 2 row.
- Updated `AUTONOMOUS-PROMPT.md`, `CONTINUE-PROMPT.md`,
  `HANDOFF-PROMPT.md`, `WAVE-OPENER-STRATEGY.md` 318 -> 319 references
  (8 sites total).
- Wrote this `CHANGELOG.md`.

## 2026-04-29 Round 4: execute follow-ups (4 parallel agents)

- **E1 SDK-matrix ownership** picked Option A: added `tickets/M07/P6.yml`
  with 6 new tickets (JVM driver, dotnet driver, Lambda driver, k8s
  driver, manifest registration + required-CI flip, cross-deployment
  smoke gate + audit-doc D07-closure marker). M07 now has P0..P6,
  40 tickets, 57.00 effort-days. Updated D07 consequences in
  `decisions.yml`, marked `RECONCILE-NEEDED.md` resolved, refreshed
  M07 narrative + `tickets/M07/README.md` + EXECUTION-BOARD section 1
  totals + Wave 3 row.
- **E2 dual-trajectory regen-codeowners** wrote new
  `.planning/trajectory-2/scripts/regen-codeowners.sh` (241 lines,
  executable) reading both `OWNERS.toml` files, merging by glob
  (union-of-reviewers + OR of `review_x2`). Self-test validates 131
  CODEOWNERS entries. Wired into `preflight-trajectory-2.sh` as item
  4a (re-runs when `CODEOWNERS` mtime is older than either OWNERS).
  Updated `WAVE-OPENER-STRATEGY.md` section 2.4 to reference the new
  script verbatim.
- **E3 M04 P3 overlapping freeze** added `overlap_with` schema to
  `freezes.yml`; documented both M04 P3 (revocation-oracle ending /
  delegation starting) and M03 P1..P2 (attest-verify / pq-primitives)
  overlap windows. Wrote new parameterized
  `ci-stubs/m04-freeze-guard.yml` (~190 lines) with milestone-filter
  yq query that automatically unions every active row; reusable for
  M03 and M10 by env-var swap. Updated EXECUTION-BOARD section 4 with
  an "Overlap windows" table; updated `audits/M04-AUDIT.md` and
  `WAVE-OPENER-STRATEGY.md` accordingly. Explicitly marked the
  `m05-adversarial-corpus-pivot` <-> `m03-attest-verify-pivot`
  policy.rs case as sequenced (NOT simultaneous) so it does NOT get
  `overlap_with`.
- **E4 NICE-TO-HAVE triage** verified zero residue. All 55 numbered
  findings + special-attention items + cross-cutting items in
  `COLD-READER-NOTES.md` already carry per-finding STATUS annotations
  from F1-F4. No edits required.

### Round 4 close-out pass (this turn)

- Removed `dashmap` from M01.P0.T1's pin list (E4-flagged residue
  from F2's partial application). M06.P0.T2 owns the watched dashmap
  single-version check per the Wave-1 lock-bump chain; M01.P0.T1
  gate_check now asserts that no duplicate dashmap pin appears in
  Cargo.toml.
- Manifest regenerated: 325 tickets, 420.25 effort-days, 61 per-phase
  files, 8,355 lines.
- Wrote this Round 4 CHANGELOG entry.

## Final integrity (post-Round 4)

- **0** em-dashes across the entire `.planning/trajectory-2/` tree.
- **0** YAML parse failures across 61 per-phase files.
- **0** duplicate ticket IDs across 325 tickets.
- **0** dangling `depends_on` references.
- **All 26** decisions D01..D26 cited consistently across narratives,
  audit templates, OWNERS, freezes, prompts.
- **All M07 P6 tickets** validate against `tickets/schema.json`
  (worktree branches `wave/W3/m07/p6.t{1..6}-...`).

## Status

trajectory-2 is **ready for Wave 1 execution**. The Wave 0 pre-flight
items in `EXECUTION-BOARD.md` section 2 remain the gating prerequisites
before any P0 wave-opener may run, but every prior follow-up flagged
during the three review rounds is now resolved.

## Open follow-ups for execution

1. ~~`RECONCILE-NEEDED.md` SDK-matrix ownership question~~ - **RESOLVED
  Round 4 E1** as M07.P6.
2. ~~`regen-codeowners.sh` dual-trajectory extension~~ - **RESOLVED
  Round 4 E2** as `.planning/trajectory-2/scripts/regen-codeowners.sh`.
3. ~~M04 P3 overlapping freeze handling~~ - **RESOLVED Round 4 E3**
  via `overlap_with` schema in `freezes.yml` and parameterized
  `m04-freeze-guard.yml` ci-stub.
  `m04-delegation-pivot` rows during the overlap window.
4. Triage the ten remaining NICE-TO-HAVE items in
  `COLD-READER-NOTES.md` that no F-agent applied (left as-is per the
  triage protocol; an orchestrator can pick them up opportunistically
  during execution).
