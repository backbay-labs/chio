# E12: Security Boundary Completion

## Status

Proposed.

## Suggested issue title

`E12: turn roots into an enforced security boundary for tools and resources`

## Problem

Chio now negotiates and tracks client roots.

That is useful, but it is not yet the same thing as enforcing a boundary.

Right now the system can say:

- what roots the client reported

But it cannot yet reliably say:

- whether a filesystem-shaped tool call or filesystem-backed resource read stayed inside those roots

That leaves a real trust gap in one of the most security-relevant parts of the MCP surface.

## Outcome

By the end of E12:

- roots are normalized and enforced as a runtime boundary, not only session metadata
- filesystem-shaped tool access outside allowed roots fails closed
- filesystem-backed resource access outside allowed roots fails closed with signed evidence
- missing, empty, stale, or unenforceable roots fail closed instead of widening filesystem access
- deny receipts preserve enough evidence to explain root-boundary enforcement decisions

## Scope

In scope:

- normalized root semantics
- root-aware tool enforcement for filesystem-shaped access
- root-aware enforcement for filesystem-backed resources
- policy and capability integration needed for root enforcement
- deny-receipt evidence for root violations

Out of scope:

- full OS sandboxing
- non-filesystem capability models unrelated to roots
- unrelated remote-hosting lifecycle work

## Primary files and areas

- `crates/chio-core/src/capability.rs`
- `crates/chio-core/src/session.rs`
- `crates/chio-kernel/src/lib.rs`
- `crates/chio-kernel/src/session.rs`
- `crates/chio-guards/src/path_normalization.rs`
- `crates/chio-guards/src/path_allowlist.rs`
- `crates/chio-guards/src/forbidden_path.rs`
- `crates/chio-policy/src/compiler.rs`
- `crates/chio-cli/src/policy.rs`
- `crates/chio-mcp-adapter/src/edge.rs`
- `docs/archive/epics/E5-nested-flows-roots-sampling-elicitation.md`

## Proposed implementation slices

### Slice A: normalized root model

Requirements:

- define how roots normalize across platforms and transports
- define how absent roots, empty roots, and non-filesystem roots behave

Frozen contract for this slice:

- only local absolute `file://` roots are enforceable for filesystem access
- `file://localhost/...` is treated the same as `file:///...`; any other file authority is not enforceable
- enforceable roots percent-decode the URI path, normalize separators, remove `.` segments, resolve `..` lexically, and preserve Windows drive roots
- non-`file` roots remain session metadata only and do not contribute to filesystem allow sets
- missing roots, explicit empty root sets, stale roots, and unenforceable file roots all mean the runtime has no provable filesystem allow set
- later tool and resource enforcement must fail closed whenever containment cannot be proven inside at least one enforceable filesystem root

Responsibilities:

- make normalization rules explicit enough for policy, guards, and receipts
- avoid hidden OS-specific behavior

### Slice B: tool-call enforcement

Requirements:

- enforce roots for filesystem-shaped tool calls and path-bearing arguments
- integrate with existing path normalization and allowlist/forbidden-path guards

Responsibilities:

- fail closed when the runtime cannot prove a path is within allowed roots
- keep error and receipt evidence understandable

### Slice C: resource enforcement

Requirements:

- distinguish filesystem-backed resources from non-filesystem resources
- enforce root boundaries on resource reads and related contextual surfaces where applicable

Responsibilities:

- preserve legitimate non-filesystem resources
- avoid pretending every URI can be mapped to a filesystem path

### Slice D: policy and capability semantics

Requirements:

- define how roots interact with grants, capabilities, and policy defaults
- document the boundary between session-provided roots and runtime policy

Responsibilities:

- keep the model least-privilege by default
- avoid ambiguous allow behavior when roots are missing or stale

## Task breakdown

### `T12.1` Freeze root normalization and threat model

- define the canonical root normalization rules
- document rootless and mixed-root session behavior
- add fixture cases for path traversal, symlinks where relevant, and normalization edge cases

### `T12.2` Enforce roots for tools

- identify tool-call shapes that imply filesystem access
- connect root checks to the kernel and guard pipeline
- emit explicit deny receipts on root violations

### `T12.3` Enforce roots for filesystem-backed resources

- classify resource reads that map to filesystem paths
- enforce root checks on those reads
- carry signed deny receipts through filesystem-backed resource denials
- preserve non-filesystem resource behavior where roots do not apply

### `T12.4` Document and test boundary semantics

- update policy docs and examples with root-aware behavior
- add direct, wrapped, and remote tests for in-root and out-of-root access
- prove that missing roots do not silently widen access

## Dependencies

- depends on E2 and E5
- should land before E13 finalizes the supported policy and operator story for roots

## Risks

- false positives from path normalization differences across platforms
- over-claiming roots as a boundary for tools whose true filesystem behavior is opaque
- surprising breakage for existing examples that assumed roots were informational

## Mitigations

- define scope explicitly around filesystem-shaped access, not every conceivable tool
- keep non-filesystem resources out of root enforcement where the model does not apply
- add clear migration notes for any behavior that becomes stricter

## Acceptance criteria

- out-of-root filesystem-shaped tool access is denied with signed evidence
- out-of-root filesystem-backed resource access is denied with signed evidence
- missing roots for filesystem-shaped or filesystem-backed access fail closed
- in-root access remains allowed when policy and capability grants permit it
- docs stop describing roots as merely session state and start describing them as an enforced boundary where applicable

## Definition of done

- implementation merged
- root-boundary enforcement is test-covered across direct, wrapped, and remote paths
- the review finding about roots as metadata-only is no longer true
