# E13: Policy and Adoption Unification

## Status

Complete.

The supported YAML path now exposes all shipped guards, including `tool_access`, `secret_patterns`, and `patch_integrity`. The canonical authoring path is now explicit for new work: HushSpec is the recommended policy format. The repo now also ships an initial native authoring surface through `NativeChioServiceBuilder` plus a maintained migration guide, canonical HushSpec example, and native example crate.

## Suggested issue title

`E13: unify the policy story and ship a higher-level authoring and migration surface`

## Problem

Chio's runtime is much closer to one canonical policy path than it used to be.

The product surface is still not fully unified:

- the guard surface is now effectively at parity across HushSpec and the supported YAML path
- canonical-versus-compatibility authoring guidance is still too implicit
- native authoring still leans on low-level provider wiring

That leaves two practical problems:

- operators do not have one obvious supported policy path
- adopters do not yet have a high-level native authoring path that matches the runtime maturity of the platform

## Outcome

By the end of E13:

- one policy path is explicitly documented as canonical
- all shipped guard capabilities are reachable through the supported policy story
- migration from wrapped MCP to native Chio is documented and example-backed
- native Chio services can be authored through a higher-level router or service abstraction

## Scope

In scope:

- policy-path convergence
- guard-surface parity on the supported path
- CLI and docs migration guidance
- examples and migration fixtures
- higher-level native authoring SDK surface

Out of scope:

- new remote transport features
- deep performance work
- release-candidate qualification outside policy and adoption impact

## Primary files and areas

- `crates/chio-cli/src/policy.rs`
- `crates/chio-policy/src/`
- `crates/chio-guards/src/`
- `examples/policies/`
- `examples/hello-tool/`
- `crates/chio-mcp-adapter`
- `docs/`
- new SDK or helper crate if added

## Proposed implementation slices

### Slice A: supported policy contract

Requirements:

- decide what operators should author by default
- document compatibility paths versus canonical paths

Responsibilities:

- reduce confusion without breaking existing inputs blindly
- make deprecation or compatibility policy explicit

### Slice B: guard-surface completion

Requirements:

- expose all shipped guards through the supported policy path
- ensure docs and examples match the actual supported surface

Responsibilities:

- avoid leaving hidden "compiler-only" or "advanced-only" guard behavior
- keep runtime behavior and user-facing configuration aligned

### Slice C: migration fixtures and docs

Requirements:

- document wrapped MCP to native Chio migration
- provide small, maintained examples that show the recommended path

Responsibilities:

- optimize for realistic incremental adoption
- keep examples grounded in actual supported semantics

### Slice D: native authoring SDK

Requirements:

- create a higher-level handler/router/service surface above the current low-level traits
- preserve access to lower-level primitives for advanced users

Responsibilities:

- improve ergonomics without hiding the security model
- keep tools, resources, prompts, and nested flows conceptually coherent

## Task breakdown

### `T13.1` Freeze the policy support story

- declare the canonical authoring path
- document compatibility behavior for the non-canonical input path
- align README, examples, and CLI messaging with that decision

### `T13.2` Complete guard exposure

- add supported-path configuration for all shipped guards
- add regression tests proving supported-path parity
- remove or clearly label any remaining split between runtime capability and user-facing configuration

### `T13.3` Ship migration guides and examples

- add wrapped-to-native migration docs
- provide example policies that reflect the supported guard surface
- connect the conformance and migration story so adoption claims are evidence-backed

### `T13.4` Add a higher-level authoring surface

- introduce a small SDK or helper layer for native providers
- cover tools, resources, prompts, and nested-flow hooks
- add at least one example that uses the new authoring surface end to end

## Dependencies

- depends on E2 and E8
- benefits from E12 so the canonical policy story includes real root-boundary semantics

## Risks

- trying to remove compatibility formats too aggressively
- freezing an SDK surface before the runtime contract is stable enough
- increasing docs volume without actually reducing operator confusion

## Mitigations

- separate canonical from compatibility rather than forcing a flag day
- keep the first SDK layer small and close to current runtime concepts
- prove adoption improvements through examples and migration fixtures

## Acceptance criteria

- docs identify one canonical policy authoring path
- all shipped guards are configurable through the supported story
- migration docs exist for wrapped MCP to native Chio adoption
- at least one higher-level native authoring example exists and is test-covered

## Definition of done

- implementation and docs merged
- the review finding about split policy surface is materially addressed
- teams evaluating Chio can tell what to author, how to migrate, and how to build a native service without reading internal crates first
