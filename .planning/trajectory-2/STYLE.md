# trajectory-2 Authoring Contract

This document is the source-of-truth style guide for every milestone narrative
and ticket file in `.planning/trajectory-2/`. Read it before authoring or
editing trajectory-2 artifacts.

## House rules (inherited from `/CLAUDE.md`)

- No em dashes (U+2014) anywhere. Use hyphens or parentheses.
- Fail-closed posture in all designs; errors deny by default.
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, etc.).
- Clippy: `unwrap_used = "deny"` and `expect_used = "deny"` are workspace-wide.
- All code-symbol references use absolute paths from the repo root.

## Milestone narrative file (`{NN}-{slug}.md`)

Each milestone has exactly one narrative doc at the trajectory-2 root. Sections,
in order:

1. **Title.** `# Milestone {NN}: {Human Title}`
2. **Lens.** One paragraph naming the dominant viewpoint (security, perf, DX,
   quality, adoption, economic-layer, etc.). One lens per milestone; if you find
   yourself naming two, the milestone is too big.
3. **Why this is on the trajectory.** Anchor to what trajectory-1 (M01-M10)
   delivered or left exposed. Cite the specific shipped artifact (crate,
   commit, schema, ticket id) that creates the precondition for this milestone.
4. **Prior-art reckoning.** Honest accounting of what trajectory-1 already
   shipped that overlaps with this milestone. State what is preserved vs what
   is changed. If a milestone re-attacks a deliberately bounded retreat
   (e.g. v3.18 walking back recursive delegation), say so.
5. **Hard counts (measured YYYY-MM-DD).** Reproduce-with-this-command numbers:
   crate sizes, missing schema entries, fuzz-target counts, kani harness
   counts, etc. Pin a date. Future readers can re-run and update.
6. **Workspace dependency state.** Crates added or pinned by this milestone,
   with a one-line rationale per pin. Reuse trajectory-1 pins where possible.
7. **Scope.** Bullet list of what is IN. Bullet list of what is OUT (and why).
8. **Phases.** One subsection per phase (P0..PN). Each phase lists its tickets
   by id and one-line title. Phase numbering matches the per-phase YAML files.
9. **Cross-milestone interactions.** Hard deps on other trajectory-2 or
   trajectory-1 artifacts. Name the artifact, not the milestone alone.
10. **Risks and mitigations.** 3-7 risks with concrete mitigations.
11. **Success criteria.** A short bulleted list of measurable artifacts that,
    once present and green, indicate the milestone is complete.

Length target: 350-700 lines. Be concrete; cite paths.

## Per-phase ticket file (`tickets/M{NN}/P{n}.yml`)

Each phase is a YAML list of ticket objects validated by
`tickets/schema.json`. Required ticket fields:

```yaml
- id: M{NN}.P{n}.T{k}            # M01.P1.T1; sub-letters allowed: T1.a, T1.b
  milestone: M{NN}
  phase: {n}                     # integer or "{n}.{m}" string for sub-phases
  title: "Imperative one-line summary, 8-200 chars"
  status: pending                # pending | in_progress | review | blocked | merged
  effort_days: 1.5               # 0.25-5; tickets above 2 days should usually be split
  owner_glob:                    # paths the ticket WRITES (>=1)
    - crates/chio-foo/src/bar.rs
  shared_paths: []               # paths the orchestrator must serialize against
  depends_on:                    # hard deps; same-trajectory ids only (M01..M10)
    - M{NN}.P{n-1}.T{k}
  soft_deps:                     # informational; cross-trajectory references go here as text
    - "trajectory-1 M07.P4.T6 (cross-provider verdict equality) is the verdict oracle"
  gate_check:
    cmd: "cargo test -p chio-foo --quiet && cargo clippy -p chio-foo -- -D warnings"
    timeout_seconds: 600         # optional; default 600
  worktree_branch: "wave/W{1-4}/m{nn}/p{n}.t{k}-{slug-2-48-chars}"
  agent_role: "kernel-rust"      # see schema.json enum
  review_required:
    - "@bb-connor"               # human-side reviewer (single-owner trajectory)
  first_commit_sha: null
  merged_sha: null
  opened_ts: null
  merged_ts: null
```

### Ticket sizing

- **0.5 days:** focused refactor or single-test addition.
- **1.0 days:** typical ticket; one feature surface, one or two test files.
- **1.5-2 days:** multi-file change with non-trivial design space.
- **>2 days:** must be split. Use `T{k}.a`, `T{k}.b` lettering to split without
  renumbering siblings.

### Naming

- `worktree_branch` slug is kebab-case, 3-49 chars after the `p{n}.t{k}-` prefix.
- Milestone slug appears in the narrative filename and the `worktree_branch`
  prefix; do not reinvent it per phase.

### Gate checks

`gate_check.cmd` is the single command CI and the orchestrator agent run to
declare a ticket green. Common patterns:

- Build + test + clippy: `cargo build -p X --quiet && cargo test -p X --quiet && cargo clippy -p X -- -D warnings`
- Schema/file existence: `test -f path/to/file && grep -q '^pattern' path/to/file`
- Specific test target: `cargo test -p X --test specific_test_module`
- WIT compile: `cargo run --quiet -p xtask -- wit-compile --check`

### Dependencies

- `depends_on` may reference only **same-trajectory-2** ticket IDs (M01-M10).
- Cross-trajectory references (e.g. "this builds on trajectory-1 M05.P3.T4
  bench gate") go in `soft_deps` as **string sentences**, not as IDs.

## Wave assignment

trajectory-2 reuses the four-wave pattern from trajectory-1:

- **Wave 1** (foundation): independent milestones that unblock others.
  Candidates: M01 (DX/error-codes), M02 (mutation+differential),
  M06 (perf hardening, mostly internal).
- **Wave 2** (trust-boundary regression nets): work that builds on Wave 1.
  Candidates: M03 (PQ + TEE quote), M04 (delegation + revocation),
  M05 (adversarial + escape + threat-model).
- **Wave 3** (breadth): adapter and runtime breadth.
  Candidates: M07 (adoption beachhead), M08 (chio-arena).
- **Wave 4** (capstone): work that depends on multiple earlier milestones.
  Candidates: M09 (economic layer + lineage), M10 (hardware custody +
  policy-bound model cards).

Express the wave in `worktree_branch` (`wave/W2/m04/...`).

## Anti-patterns

- Do NOT re-propose work that trajectory-1 already shipped. If you find
  overlap, cite it and explain what is new.
- Do NOT widen scope beyond the synthesis brief in `README.md`. If a phase
  feels essential and is out of scope, add it under "## Out" in the narrative
  and propose a follow-on milestone.
- Do NOT invent reviewer handles. Single-owner trajectory; reviewer is
  `@bb-connor`.
- Do NOT use `Cargo.lock` in `owner_glob`. It always belongs in
  `shared_paths`.
- Do NOT write per-ticket success-criteria prose in the YAML. The narrative
  has the criteria; tickets carry the gate command.
