# chio-wall-core architecture

## Overview

`chio-wall-core` is a pure contract crate: serde-derived types, enums, and
fail-closed validation, built with `#![forbid(unsafe_code)]`, no I/O, no async
runtime, and no dependency on `chio-core`, `chio-kernel`, or `chio-guards`. It
defines the JSON shape of the seven-artifact evidence bundle that the
`chio-wall` CLI builds when it runs its bounded control-path workflow. The
crate does not evaluate guards, sign receipts, or write files; it only defines
what a valid artifact looks like and rejects everything else.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API surface. Re-exports every type, enum, error, and schema constant from `control_path`. |
| `src/control_path.rs` | The seven artifact schemas, `ChioWallContractError`, `REQUIRED_CONTROL_PACKAGE_ARTIFACTS`, and the shared field-level validation helpers (`ensure_non_empty`, `ensure_non_empty_list`, `ensure_unique_strings`, `ensure_fail_closed`). |

## Boundaries

- The crate performs no I/O and holds no runtime or kernel state. It does not
  call `chio-core`, `chio-kernel`, `chio-guards`, or `chio-store-sqlite`; those
  are `chio-wall`'s dependencies, not this crate's. It only defines the JSON
  shapes those systems' outputs are projected into.
- Validation is per-artifact and structural. `ChioWallControlPackage::validate`
  checks that the required artifact-kind set is complete and non-duplicated and
  that each artifact's own fields are well-formed; it does not read the files
  named by `relative_path`, and it does not cross-check `workflow_id` or other
  fields for equality across sibling artifacts.
- File writing, Chio evidence export, guard-pipeline execution, and receipt
  signing all live in `chio-wall`. See `docs/chio-wall/VALIDATION_PACKAGE.md`
  for the CLI's output layout, which is a superset of what this crate models:
  it also writes a `control-path-summary.json` that has no corresponding type
  here.

## Invariants and failure modes

- The seven schema-tagged types (`ChioWallControlProfile`, `ChioWallPolicySnapshot`,
  `ChioWallAuthorizationContext`, `ChioWallGuardOutcome`, `ChioWallDeniedAccessRecord`,
  `ChioWallBuyerReviewPackage`, `ChioWallControlPackage`) each fail closed on a
  schema-tag mismatch (`InvalidSchema`) before checking any other field.
  `ChioWallArtifact`, the artifact-reference type embedded in
  `ChioWallControlPackage.artifacts`, carries no schema field and only
  validates `relative_path`.
- `ChioWallBuyerMotion` and `ChioWallControlSurface` are each single-variant
  enums, so the one-buyer-motion, one-control-surface scope is enforced by the
  type system rather than by a runtime check.
- String fields fail closed on empty, whitespace-padded, or control-character
  content (`EmptyField`, `PaddedField`, or a `Validation` error); string lists
  additionally fail closed on any element with those defects.
- `fail_closed` fields (on `ChioWallControlProfile`, `ChioWallPolicySnapshot`,
  `ChioWallGuardOutcome`, `ChioWallBuyerReviewPackage`, `ChioWallControlPackage`)
  must be `true`; `ensure_fail_closed` rejects `false` even though the struct
  itself allows constructing one.
- Domain-pair fields must differ: `ChioWallControlProfile.source_domain` /
  `protected_domain`, and `requested_domain` / `source_domain` on both
  `ChioWallAuthorizationContext` and `ChioWallDeniedAccessRecord`.
- `ChioWallGuardOutcome` rejects a `Deny` decision whose `evaluated_tool` also
  appears in `allowed_tools`. Both `ChioWallPolicySnapshot.allowed_tools` and
  `ChioWallGuardOutcome.allowed_tools` must be non-empty with no duplicates.
- `ChioWallControlPackage::validate` requires exactly the seven
  `REQUIRED_CONTROL_PACKAGE_ARTIFACTS` kinds present with no duplicate
  `ChioWallArtifactKind`.
- `serde_json::Error` converts into `ChioWallContractError::Json` via `From`,
  so JSON parse failures surface through the same error type as validation.

## Dependencies

No internal `chio-*` dependencies; this is a workspace leaf crate. External:
`serde` / `serde_json` for the artifact schemas (`camelCase` fields,
`snake_case` enum variants) and `thiserror` for `ChioWallContractError`.
