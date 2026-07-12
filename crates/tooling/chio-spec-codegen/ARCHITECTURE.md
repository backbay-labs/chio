# chio-spec-codegen Architecture

## Boundaries

- `src/lib.rs` owns Rust schema discovery, local `$ref` inlining, typify registration, prettyplease formatting, generated header stamping, and shared file writes.
- `src/errors_pass.rs` owns the Chio error registry parser and generated `chio-errors` Rust output.
- `src/statemachines_pass.rs` owns TOML loading, graph validation, generated typestates, conformance relations, reference tables, and complete managed-output drift checks.
- `src/threat_model.rs` owns threat-model JSON loading, optional schema validation, and per-threat stub generation.
- `src/threat_coverage_doc.rs` owns the generated markdown coverage report that joins threat-model rows, adversarial corpus cases, and existing threat tests.
- `src/main.rs` is a CLI dispatcher over the library entry points.

## Security And API Constraints

- The generator consumes trusted repository inputs and emits Rust source that downstream crates compile.
- Codegen must be deterministic: sorted schema files, stable headers, rustfmt or prettyplease formatting, and write-if-changed output.
- State-machine inputs reject unknown or unreachable states, dead non-terminal states, duplicate edges, duplicate guards, unsafe owner paths, and output collisions.
- Generated stage fields remain private and transitions consume the prior stage. Runtime guards delegate to hand-written handlers.
- Local schema references must stay under the configured schema tree. Symlinks and path escapes must fail closed.
- Network schema references must not become ambient authority or typify-side fallback behavior.
- Existing public entry points and generated header bytes must remain compatible.

## Schema Reference Resolution

`resolve_local_schema_ref` validates local filesystem references against the configured schema tree. Absolute `http` and `https` `$ref`s are rejected as a `SchemaRef` denial during the schema pre-pass, before typify generation, rather than left to fail as a backend-specific typify error. Internal fragment refs and local cross-file inlining are preserved.
