# chio-spec-codegen Architecture

## Boundaries

- `src/lib.rs` owns Rust schema discovery, local `$ref` inlining, typify registration, prettyplease formatting, generated header stamping, and shared file writes.
- `src/errors_pass.rs` owns the Chio error registry parser and generated `chio-errors` Rust output.
- `src/threat_model.rs` owns threat-model JSON loading, optional schema validation, and per-threat stub generation.
- `src/threat_coverage_doc.rs` owns the generated markdown coverage report that joins threat-model rows, adversarial corpus cases, and existing threat tests.
- `src/main.rs` is a CLI dispatcher over the library entry points.

## Security And API Constraints

- The generator consumes trusted repository inputs and emits Rust source that downstream crates compile.
- Codegen must be deterministic: sorted schema files, stable headers, rustfmt or prettyplease formatting, and write-if-changed output.
- Local schema references must stay under the configured schema tree. Symlinks and path escapes must fail closed.
- Network schema references must not become ambient authority or typify-side fallback behavior.
- Existing public entry points and generated header bytes must remain compatible.

## Pain Points

- `resolve_local_schema_ref` validates local filesystem references, but absolute `http` or `https` `$ref`s are currently ignored by the pre-pass and left for typify.
- That makes the crate boundary less explicit than `chio-spec-validate`: an external ref should be a `SchemaRef` denial before generation, not a backend-specific typify failure.

## Planned Improvement

Reject absolute network `$ref`s during the schema pre-pass while preserving internal fragment refs and existing local cross-file inlining.
