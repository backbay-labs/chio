# E0: Program Setup and Architectural Decisions

## Suggested issue title

`E0: lock architecture decisions and execution scaffolding`

## Why this exists

The execution plan has five blocking design decisions. Work should not start scattering across protocol, trust, and compatibility code without those being written down.

This epic creates the minimal governance needed to keep later implementation work aligned.

## Outcome

By the end of E0:

- D1 through D5 are documented as ADRs
- planning artifacts have a stable home in the repo
- the first implementation epics can proceed without reopening foundational questions

## Scope

In scope:

- ADRs
- execution artifact structure
- milestone naming and tracking conventions
- definition of done template for technical work

Out of scope:

- implementation of session code
- implementation of policy unification
- MCP edge work

## Primary files and areas

- `docs/adr/`
- `docs/archive/epics/`
- `docs/EXECUTION_PLAN.md`
- `docs/ROADMAP_V1.md`

## Task breakdown

### `T0.1` Create ADR directory and index

- add `docs/adr/README.md`
- define status vocabulary

### `T0.2` Write ADR for edge protocol shape

- file: `docs/adr/ADR-0001-edge-protocol-shape.md`

### `T0.3` Write ADR for scope evolution timing

- file: `docs/adr/ADR-0002-scope-evolution-timing.md`

### `T0.4` Write ADR for nested flow model

- file: `docs/adr/ADR-0003-nested-flow-model.md`

### `T0.5` Write ADR for first receipt backend

- file: `docs/adr/ADR-0004-first-receipt-backend.md`

### `T0.6` Write ADR for MCP edge runtime location

- file: `docs/adr/ADR-0005-mcp-edge-runtime-location.md`

### `T0.7` Create epic-spec directory and first epic docs

- add `docs/archive/epics/README.md`
- add issue-ready docs for E1 and E2

### `T0.8` Link all artifacts from existing docs

- update `docs/research/README.md`
- update `docs/ROADMAP_V1.md`
- keep `docs/EXECUTION_PLAN.md` as the execution center

## Dependencies

- none

## Acceptance criteria

- all five decision gates from the execution plan exist as ADRs
- all ADRs contain context, decision, consequences, and follow-up work
- epic docs exist for E1 and E2 in issue-ready form
- roadmap and research index link to the new artifacts

## Definition of done

- docs merged
- links valid
- later epics can reference ADR IDs instead of re-explaining the decisions
