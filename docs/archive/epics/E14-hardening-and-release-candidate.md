# E14: Hardening and Release Candidate

## Status

Implemented locally. The repo now has release qualification and release-audit artifacts under `docs/release/`, with the remaining procedural step being hosted CI observation on the updated workflows before tagging from `main`.

## Suggested issue title

`E14: qualify Chio for release with explicit guarantees, limits, and failure-mode coverage`

## Problem

By the time E9 through E13 land, Chio should have closed the major semantic gaps identified in the post-review plan.

That still does not automatically make it release-ready.

The repo needs one explicit close-out epic that proves:

- the supported surface is stable under the real workspace and CI gates
- failure modes are tested and documented
- operator and adopter docs describe what Chio actually guarantees
- the final release story is driven by evidence rather than by leftover optimism

Without that, "hardening" becomes a vague catch-all bucket and the closing cycle never really ends.

## Outcome

By the end of E14:

- the supported feature matrix, non-goals, and extension policy are explicit
- release qualification covers the real failure modes, not only happy-path conformance
- CI and local qualification runs back the release claims with repeatable evidence
- the remaining open questions are product choices, not unresolved architectural blockers

## Scope

In scope:

- release qualification matrix
- failure-mode and limit testing
- security and operator-facing release docs
- supported feature and extension policy
- final milestone audit and go/no-go evidence

Out of scope:

- brand-new core features that should have landed in E9 through E13
- a new distributed-control architecture
- theorem-prover completion for the full draft spec

## Primary files and areas

- `.github/workflows/ci.yml`
- `README.md`
- `docs/POST_REVIEW_EXECUTION_PLAN.md`
- `docs/EXECUTION_PLAN.md`
- `docs/ROADMAP_V1.md`
- `docs/archive/epics/`
- `crates/chio-cli/tests/`
- `crates/chio-conformance/tests/`
- `tests/e2e/`
- release-facing examples and policy fixtures

## Proposed implementation slices

### Slice A: qualification matrix

Requirements:

- define which gates, environments, and supported behaviors constitute release qualification
- map each remaining post-review finding to a concrete pass/fail artifact

Responsibilities:

- do not let release readiness depend on undocumented tribal knowledge
- keep qualification tied to user-visible guarantees

### Slice B: failure modes and limits

Requirements:

- add coverage for malformed input, revocation/expiry paths, stream interruption, nested denial/cancel races, and operational limits
- capture the supported size, lifetime, and concurrency limits that operators can reasonably rely on

Responsibilities:

- test the negative paths the same way the happy paths are tested
- avoid claiming limits that are not measured or at least intentionally bounded

### Slice C: release docs

Requirements:

- publish supported feature matrix, non-goals, migration story, and extension policy
- align README, roadmap docs, and epic close-out notes around the same release claims

Responsibilities:

- keep docs honest about what is still intentionally not solved
- make adoption decisions possible without reading internal crates first

### Slice D: final milestone audit

Requirements:

- prove E9 through E13 outcomes are actually achieved
- capture final blockers, waivers, or go/no-go decision evidence

Responsibilities:

- prevent unresolved core semantics from being hidden inside release framing
- leave a crisp handoff into whatever milestone follows `v1.0`

## Task breakdown

### `T14.1` Build the release qualification matrix

- define the release gates and required evidence
- map each supported feature and each former finding to a proving artifact
- identify any remaining unknowns as explicit blockers or waivers

### `T14.2` Add failure-mode and limits coverage

- add tests for malformed JSON-RPC, revoked/expired capabilities, interrupted streams, and nested-flow denial/cancellation races
- capture supported limits for local and remote modes
- ensure CI and local qualification can run the agreed release gates

### `T14.3` Publish release-facing docs

- document the supported feature matrix
- document explicit non-goals and extension policy
- align README, roadmap, epic, and migration docs with the release candidate story

### `T14.4` Run the final audit and release-candidate decision

- verify the closing-cycle requirements are actually complete
- record any blockers or accepted waivers
- produce the final go/no-go recommendation for the milestone

## Dependencies

- depends on E9, E10, E11, E12, and E13
- should remain a true close-out epic, not a place to finish core behavior that belonged earlier

## Risks

- treating hardening as a vague cleanup phase instead of a proof phase
- papering over unresolved semantics with release language
- adding too many last-minute tests or docs without a coherent qualification model

## Mitigations

- freeze the qualification matrix before calling the milestone release-ready
- keep every release claim mapped to an observable artifact
- force unresolved issues into explicit blockers or waivers instead of vague follow-up notes

## Acceptance criteria

- release docs identify supported guarantees, limits, and non-goals clearly
- CI and local qualification runs back those claims with repeatable evidence
- failure-mode coverage exists for the major negative paths in the supported surface
- no post-review finding is left as an undefined "hardening later" bucket

## Definition of done

- implementation and release docs merged
- a milestone audit records the release-candidate decision and any explicit waivers
- the repo has a concrete release story rather than a generic hardening placeholder
