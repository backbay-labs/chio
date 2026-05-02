# trajectory-3 Authoring Contract

This document is the source-of-truth style guide for every milestone narrative
and ticket file in `.planning/trajectory-3/`. Read it before authoring or
editing trajectory-3 artifacts.

## House rules (inherited from `/CLAUDE.md`)

- No em dashes (U+2014) anywhere. Use hyphens or parentheses.
- Fail-closed posture in all designs; errors deny by default.
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, etc.).
- Clippy: `unwrap_used = "deny"` and `expect_used = "deny"` are workspace-wide.
- All code-symbol references use absolute paths from the repo root.

## Milestone narrative file (`{NN}-{slug}.md`)

Each milestone has exactly one narrative doc at the trajectory-3 root.
Sections, in order:

1. **Title.** `# Milestone {NN}: {Human Title}`
2. **Lens.** One paragraph naming the dominant viewpoint
   (adoption / quality / security / formal / external-attestation /
   distribution / platform-expansion). One lens per milestone.
3. **Why this is on the trajectory.** Anchor to the verdict and to what
   trajectory-2 (M01-M10) delivered or left exposed. Cite the specific
   shipped artifact, gap, or external dependency that creates the
   precondition for this milestone.
4. **Prior-art reckoning.** Honest accounting of what trajectory-2 already
   shipped that overlaps with this milestone. State what is preserved vs
   what is changed. Customer-anchored milestones must name the customer
   explicitly; external-attestation milestones must name the vendor
   shortlist explicitly.
5. **Hard counts (measured YYYY-MM-DD).** Reproduce-with-this-command
   numbers where the milestone is anchored to live state (mutation
   kill-rate today, threat-coverage row count, build reproducibility
   percentage). Pin a date. Future readers can re-run and update.
6. **Workspace dependency state.** Crates added or pinned by this
   milestone, with a one-line rationale per pin. Reuse trajectory-2 pins
   where possible. External-attestation milestones list vendor calendar
   lead times here, not crates.
7. **Scope.** Bullet list of what is IN. Bullet list of what is OUT
   (and why). Customer-anchored milestones cite the design-partner
   ask explicitly; external-attestation milestones cite the deferred
   evidence forms explicitly (e.g. SOC 2, ISO 27001).
8. **Phases.** One subsection per phase (P0..PN). Each phase lists its
   tickets by id and one-line title. Phase numbering matches the
   per-phase YAML files. Vendor calendar milestones (M08, M09) carry
   weeks-from-trajectory-start markers per phase.
9. **Cross-milestone interactions.** Hard deps on other trajectory-3 or
   trajectory-2 artifacts. Name the artifact, not the milestone alone.
10. **Risks and mitigations.** 3-7 risks with concrete mitigations.
    Trajectory-3-specific risks (design-partner withdrawal, vendor
    calendar slip, HITRUST assessor rejection, M08 reviewer critical CVE) get
    explicit halt-trigger references.
11. **Success criteria.** A short bulleted list of measurable artifacts
    that, once present and green, indicate the milestone is complete.
    External-attestation milestones cite the third-party evidence
    document explicitly.

Length target: 350-700 lines for code milestones; 250-450 lines for
external-attestation milestones (M08, M09) since their content is
calendar-driven, not implementation-driven. Be concrete; cite paths.

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
    - "trajectory-2 M07.P4.T6 (cross-provider verdict equality) is the verdict oracle"
  gate_check:
    cmd: "cargo test -p chio-foo --quiet && cargo clippy -p chio-foo -- -D warnings"
    timeout_seconds: 600         # optional; default 600
  worktree_branch: "wave/W{1-3}/m{nn}/p{n}.t{k}-{slug-2-48-chars}"
  agent_role: "kernel-rust"      # see schema.json enum
  review_required:
    - "@bb-connor"               # human-side reviewer
  first_commit_sha: null
  merged_sha: null
  opened_ts: null
  merged_ts: null
```

### Ticket sizing

- **0.5 days:** focused refactor, single-test addition, vendor email.
- **1.0 days:** typical ticket; one feature surface, one or two test files.
- **1.5-2 days:** multi-file change with non-trivial design space.
- **>2 days:** must be split. Use `T{k}.a`, `T{k}.b` lettering to split
  without renumbering siblings.

External-attestation milestones (M08, M09) often carry low-effort
"vendor wait" tickets at 0.25 days that capture the calendar dependency
without implying engineering work.

Vendor-bookended tickets MAY seed as `status: vendor_wait` when the
external calendar has already been initiated (typically week 1) and
runs in parallel to engineering work. M03.P5.T2 (third-party rebuilder
engagement) and M10.P0.T2 (Apple Developer Program / APN registration)
are the canonical examples: each names a vendor-side calendar that
starts at trajectory open, so seeding as `vendor_wait` correctly
encodes the dependency without falsely signaling "pending engineering".

### Naming

- `worktree_branch` slug is kebab-case, 3-49 chars after the `p{n}.t{k}-`
  prefix.
- Milestone slug appears in the narrative filename and the
  `worktree_branch` prefix; do not reinvent it per phase.

### Gate checks

`gate_check.cmd` is the single command CI and the orchestrator agent run
to declare a ticket green. Common patterns:

- Build + test + clippy: `cargo build -p X --quiet && cargo test -p X --quiet && cargo clippy -p X -- -D warnings`
- Schema/file existence: `test -f path/to/file && grep -q '^pattern' path/to/file`
- Specific test target: `cargo test -p X --test specific_test_module`
- Vendor evidence: `test -f .planning/trajectory-3/audits/M{NN}-vendor-evidence.md && grep -q 'received_on' ...`

### Dependencies

- `depends_on` may reference only **same-trajectory-3** ticket IDs (M01-M10).
- Cross-trajectory references (e.g. "this builds on trajectory-2 M07.P4.T6
  cross-provider verdict equality") go in `soft_deps` as **string sentences**,
  not as IDs.

## Wave assignment

trajectory-3 uses a three-wave pattern plus two long-clock vendor lanes:

- **Wave 1** (debt + pilot + CI): M01, M02, M03, M04, M05 (weeks 1-15).
- **Wave 2** (formal + mobile): M06, M07 (weeks 12-26).
- **Wave 3** (distribution): M10 (weeks 22-30).
- **Vendor calendars** (parallel, no wave): M08, M09 start week 1.

Express the wave in `worktree_branch` (`wave/W2/m07/...`).
M08 / M09 use `wave/Wv/m08/...` and `wave/Wv/m09/...` (`v` = vendor).

## Anti-patterns

- Do NOT re-propose work that trajectory-2 already shipped. If you find
  overlap, cite it and explain what is new.
- Do NOT widen scope beyond the verdict-anchored brief in `README.md`.
  If a phase feels essential and is out of scope, add it under
  "## Out" in the narrative and propose a follow-on milestone for
  trajectory-4.
- Do NOT invent reviewer handles. Single-owner trajectory; reviewer is
  `@bb-connor`.
- Do NOT use `Cargo.lock` in `owner_glob`. It always belongs in
  `shared_paths`.
- Do NOT write per-ticket success-criteria prose in the YAML. The
  narrative has the criteria; tickets carry the gate command.
- Do NOT silently widen the verdict. If a milestone wants to chase
  three clouds instead of one, that is D03-violating scope creep and
  must surface as an explicit decision amendment.
