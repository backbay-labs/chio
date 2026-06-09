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

## Pain Points

- The export path validates in-memory objects before writing them, but the CLI
  reports success without reading the completed package back from disk.
- The operations runbook says the package is incomplete if files are missing,
  inconsistent, or unresolved. That is a wrapper-owned invariant because only
  the CLI sees the final file layout and Chio evidence directory.
- `commands.rs` is large because it currently mixes object construction,
  evidence export, file writes, output summaries, and tests in one module.

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

## Affected Dependents

- `crates/chio-wall-core` remains the source of typed contract validation.
- CLI tests under `crates/chio-wall/tests` exercise exported on-disk packages.
- Documentation under `docs/chio-wall` is the source of truth for output layout
  and fail-closed operating expectations.

## Completed Post-Write Reconciliation Slice

Add a post-write reconciliation boundary to `export_control_path`: after the
CLI writes the control-path package and Chio evidence export, read the package
back from disk, validate the typed contracts, verify cross-file consistency, and
fail before printing success if any required artifact or evidence directory is
missing.

## Package Closure Slice

### Current Boundary

`verify_control_path_export` confirms that the required Chio-Wall files exist,
the Chio evidence directory is non-empty, typed contracts validate, and declared
cross-file references agree. It does not reject undeclared top-level files in
the generated package directory.

### Pain Point

The export command creates a transient SQLite receipt database before producing
the evidence bundle. If that file or any other unexpected artifact remains in
the output root, the package can still be reported as valid even though the
buyer-facing package contains material outside the declared control-path
contract.

### Planned Improvement

Add a package-closure check that fails reconciliation when the output root
contains any undeclared top-level entry. Keep evidence-export internals scoped
inside `chio-evidence`; only the Chio-Wall package root is closed.
