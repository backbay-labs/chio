# E2: Canonical Policy Runtime

## Suggested issue title

`E2: make HushSpec and compiled policy the runtime truth`

## Problem

The repository already contains the richer policy system in `chio-policy`, but the CLI and runtime still center the original Chio YAML path. That creates:

- split-brain runtime behavior
- duplicated policy semantics
- lost value from the HushSpec compiler

## Outcome

By the end of E2:

- HushSpec is a first-class runtime input
- compiled policy survives loading and actually drives kernel construction
- receipt policy identity is based on runtime-meaningful policy state

## Scope

In scope:

- policy loading refactor
- `LoadedPolicy` or equivalent runtime type
- HushSpec compilation wired into guard pipeline and default scope construction
- policy hash semantics clarification
- canonical policy fixtures

Out of scope:

- full MCP edge
- resource and prompt grant shapes
- policy UX polish beyond what is needed for correctness

## Primary files and areas

- `crates/chio-cli/src/policy.rs`
- `crates/chio-cli/src/main.rs`
- `crates/chio-policy/src/`
- `crates/chio-kernel/src/lib.rs`
- `examples/policies/`

## Proposed implementation slices

### Slice A: loaded policy abstraction

Candidate shape:

```rust
enum LoadedPolicy {
    ChioYaml(ChioPolicy),
    HushSpec {
        spec: HushSpec,
        compiled: CompiledPolicy,
    },
}
```

### Slice B: kernel construction path

Goal:

- one code path from loaded policy to kernel config, guard pipeline, and default scope

### Slice C: receipt policy identity

Goal:

- define whether receipt policy identity uses:
  - source file hash
  - compiled policy hash
  - both

Recommended:

- keep source-file hash available for traceability
- add compiled-policy identity for enforcement truth

## Task breakdown

### `T2.1` Introduce runtime loaded-policy type

- add `LoadedPolicy` or equivalent
- update CLI load path to return it

### `T2.2` Wire HushSpec compilation into kernel setup

- consume `CompiledPolicy` directly
- remove fake default fallback for HushSpec inputs

### `T2.3` Clarify receipt policy identity

- implement compiled-policy identity
- update receipt construction and tests as needed

### `T2.4` Add policy fixtures

- allow-by-default tool fixture
- deny-by-default fixture
- guard-heavy fixture
- resource/prompt placeholder fixtures for future phases

### `T2.5` Add regression tests

- HushSpec and Chio YAML behavior comparison where appropriate
- deterministic policy identity tests
- guard coverage compilation tests

## Dependencies

- depends on ADR-0002 indirectly for future scope work
- can run in parallel with E1 after E0 completes

## Risks

- accidental breakage of existing example policies
- hidden assumptions in CLI/kernel setup about the original Chio YAML policy shape

## Mitigations

- keep compatibility input path for Chio YAML policies
- add explicit test fixtures before refactor completion

## Acceptance criteria

- HushSpec policies no longer validate and then fall back to empty runtime behavior
- compiled policy drives guard and default-scope setup
- receipts carry a stable policy identity tied to runtime meaning
- tests cover both Chio YAML and HushSpec load paths

## Definition of done

- implementation merged
- policy fixtures added
- docs updated where policy behavior changed
- future epics can depend on one canonical runtime policy path
