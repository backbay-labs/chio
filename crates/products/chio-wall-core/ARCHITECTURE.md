# chio-wall-core Architecture

`chio-wall-core` owns the typed Chio-Wall control-path contracts layered on Chio
guard and receipt truth. Chio-Wall is a bounded companion product over the Chio
substrate, separate from MERCURY and separate from generic information-barrier
platform claims.

## Boundaries

- `control_path.rs` owns all public Chio-Wall schemas, product enums, validation
  errors, artifact references, buyer-review packages, and control packages.
- `lib.rs` is the compatibility re-export surface for the CLI and tests.
- `crates/chio-wall` owns command orchestration, file output, Chio evidence
  export, and JSON rendering. It should not duplicate core package invariants.
- `docs/chio-wall/*` owns product scope, supported claims, output layout, and
  non-claims for the bounded buyer motion.

## Pain Points

- `ChioWallControlPackage::validate` now requires the complete bounded artifact
  set described in `docs/chio-wall/VALIDATION_PACKAGE.md`, but the foundational
  string validators still allow embedded control characters.
- List validators reject empty allowlist entries, but they do not yet reject
  padded or control-bearing entries that would be invalid as stable package
  identifiers and reviewer-facing evidence fields.
- The crate intentionally has a small surface, so validation drift tends to
  concentrate in helper functions rather than module boundaries.

## Security And API Constraints

- Preserve the public structs, enum variants, schema names, and field names.
- Validation must fail closed for missing package evidence, duplicate artifact
  kinds, malformed paths, same-domain requests, and `fail_closed=false`.
- Chio-Wall must remain a narrow product lane: one buyer motion, one control
  surface, one research-to-execution denied access event, and one package family.
- Do not move Chio evidence export semantics into this crate. The core crate can
  validate package contracts; the CLI remains responsible for writing files and
  exporting Chio evidence.

## Affected Dependents

- `crates/chio-wall` exports and validates packages through these core types.
- `docs/chio-wall/VALIDATION_PACKAGE.md` defines the artifact layout the core
  validator should enforce.
- Tests under `crates/chio-wall/tests` are the dependent gate for CLI-generated
  packages.

## Planned Improvement

Harden foundational string validation across the Chio-Wall contracts. Scalar
fields that already reject empty and padded values must also reject control
characters, and non-empty string lists must reject padded or control-bearing
entries before package data reaches CLI artifact generation or reviewer output.
