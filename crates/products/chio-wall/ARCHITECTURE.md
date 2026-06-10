# chio-wall Architecture

`chio-wall` owns the Chio-Wall companion-product CLI. It is the file and command
orchestration layer over `chio-wall-core`, Chio guard evaluation, receipt
creation, SQLite-backed evidence export, and validation-package rendering.

## Boundaries

- `src/main.rs` owns the clap command surface and keeps routing thin.
- `src/commands.rs` owns control-path export, validation-package generation,
  temporary receipt database creation, Chio evidence export, and operator output.
- `chio-wall-core` owns typed package contracts and schema-level validation.
  This CLI should call those validators instead of duplicating schema rules.
- `docs/chio-wall/*` defines the bounded product claim, required output layout,
  fail-closed operations, and deferred scope.

## Post-Write Reconciliation

`export_control_path` does not report success on in-memory validation alone.
After writing the control-path package and Chio evidence export,
`verify_control_path_export` reads the package back from disk, validates the
typed contracts, verifies cross-file consistency, and fails before printing
success if any required artifact or evidence directory is missing. Package-layout
completeness is a wrapper-owned invariant because only the CLI sees the final
file layout and Chio evidence directory.

Reconciliation also closes the package root: `ensure_only_expected_package_entries`
fails if the output root contains any undeclared top-level entry, so the
transient SQLite receipt database or any stray artifact cannot leave material
outside the declared control-path contract. Evidence-export internals stay scoped
inside `chio-evidence`; only the Chio-Wall package root is closed.

`commands.rs` is large because it mixes object construction, evidence export,
file writes, output summaries, and tests in one module.

## Security And API Constraints

- Preserve the current CLI surface: `control-path export`, `control-path
  validate`, `--output`, and global `--json`.
- Preserve the bounded Chio-Wall product lane: one buyer motion, one control
  surface, one research-to-execution denied access event, and one evidence
  package.
- Fail closed if generated package files, references, owners, workflow IDs,
  policy bindings, denied-access records, or Chio evidence directories are
  missing or inconsistent.
- Do not move Chio evidence export semantics into `chio-wall-core`; the CLI owns
  file-system reconciliation while the core crate owns typed contracts.

## Dependents

- `crates/products/chio-wall-core` remains the source of typed contract validation.
- CLI tests under `crates/products/chio-wall/tests` exercise exported on-disk packages.
- Documentation under `docs/chio-wall` is the source of truth for output layout
  and fail-closed operating expectations.
