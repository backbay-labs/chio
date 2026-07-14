# chio-spec-codegen architecture

## Overview

`chio-spec-codegen` is an offline, build-time tool: it runs in local
development and CI against repository-tracked spec files and writes
generated Rust and markdown back into the tree. It never links into a
running kernel, client, or guard, and never touches untrusted network input.
The crate is four independent generator passes (wire types, error registry,
threat-model stubs, threat-coverage doc) sharing one binary, one
`CodegenError` type, and the `write_if_changed` helper that keeps
regeneration idempotent and diff-free. Byte-for-byte reproducibility is the
core design constraint: identical input must render identical output so the
`--check` drift lanes in CI are meaningful.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Wire-type pass: schema discovery, local `$ref` inlining and hazard checks, typify registration, prettyplease formatting. Also hosts `CodegenError`, `GENERATED_HEADER`, and the shared `write_if_changed`. |
| `src/errors_pass.rs` | Error-registry pass: hand-rolled `registry.yaml` parser, validation, and Rust rendering (formatted via a shelled-out `rustfmt`). Private module, re-exported at the crate root. |
| `src/threat_model.rs` | Threat-model pass: JSON loading, JSON Schema validation, and per-threat stub rendering with doc-comment injection sanitization. |
| `src/threat_coverage_doc.rs` | Threat-coverage-doc pass: joins the threat model, the adversarial-suite manifest, and stub-file presence into a markdown report. |
| `src/main.rs` | CLI dispatcher; one subcommand per pass. |
| `tests/threat_model_schema_test.rs` | Integration test validating the checked-in threat-model instance against its schema. |

## Generator passes

### Wire types (`codegen_rust`, `render_chio_wire_v1`)

1. Walk `schemas_dir`, collect `*.schema.json` files, sort lexicographically.
2. Find local `$ref` targets that point at another file's root and skip
   those files as top-level schemas (`collect_local_schema_ref_roots`), so a
   schema that exists only to be referenced is not also registered standalone.
3. For each remaining file, inline local cross-file `$ref`s and `$defs`
   (fail closed on symlinks, absolute-URI refs, or a resolved path outside
   `schemas_dir`), strip typify-unsupported `if`/`allOf` conditionals, parse
   as `schemars::schema::RootSchema`, and register with one shared `TypeSpace`.
4. Render the `TypeSpace` to tokens, parse as `syn::File`, format with
   `prettyplease`, prepend `GENERATED_HEADER`, and write `chio_wire_v1.rs`
   plus a header-only `mod.rs` via `write_if_changed`.

### Error registry (`codegen_error_codes`, `render_error_codes`)

1. Parse `spec/errors/registry.yaml` line by line against the registry's own
   indentation rules (top-level scalars, `domains:`, `codes:`, a
   `consumed_by:` sequence) - not a general YAML parser.
2. Validate: schema discriminator, non-empty domains/codes, known domain and
   severity enums, URN prefix matches its domain, unique URNs and generated
   constant names, non-empty required fields, non-empty `consumed_by`.
3. Render `pub const <NAME>: ErrorCodeSpec` per code plus `lookup_error_code`
   / `lookup_string_code` / `lookup_jsonrpc_code`, parse-check the buffer
   with `syn`, then format by shelling out to `rustfmt --emit stdout`.
4. Write `error_codes.rs` and a header-only `mod.rs` under `ERRORS_GENERATED_DIR`.

### Threat-model stubs (`codegen_threat_model`)

1. Load `spec/security/chio-threat-model.v1.json`, checking the
   `chio.threat-model.v1` schema discriminator; the CLI additionally runs
   full JSON Schema validation when a sibling schema file exists.
2. For each threat ID (must be snake_case), render a stub test whose doc
   comment interpolates `name` and `surfaces`, sanitized against control
   characters, U+2028/U+2029, and `*/` runs so a crafted field cannot break
   out of the comment into top-level Rust.
3. Skip any file that no longer contains a live `unimplemented!()` marker,
   so a hand-written test body is never clobbered; always refresh the
   doc-only `mod.rs` aggregator.

### Threat-coverage doc (`codegen_threat_coverage_doc`, `_default`)

1. Load the threat model and the adversarial-suite manifest (a missing
   manifest is treated as zero cases, not an error).
2. Index manifest cases by `threat_id`; group threats by `coverage_state`
   (`covered` default, `partial`, `pending`, `weak_coverage`).
3. Render a status summary, a coverage-state legend, and one
   `## Threat: <id>` section per threat with its stub-test path, corpus
   cases, and (for three fixed threat IDs) the wasm-guard escape-harness pointer.
4. Write `docs/security/threat-coverage.md`.

## Invariants and failure modes

- Fail closed throughout: malformed YAML/JSON, unknown enum values, and
  schema violations return `CodegenError` variants, never a panic.
  `#![forbid(unsafe_code)]`; workspace clippy denies `unwrap()`/`expect()`
  outside `#[cfg(test)]`.
- Local schema `$ref`s must canonicalize to a path inside `schemas_dir`;
  symlinked schema files and absolute-URI `$ref`s are rejected before
  typify sees them.
- `write_if_changed` writes only when computed bytes differ from disk, so
  `--check` modes (xtask's Rust and error-registry drift checks) can diff a
  temp-staged regeneration against the working tree byte-for-byte.
- `codegen_threat_model` is one-shot per file: once a stub's
  `unimplemented!()` marker is replaced by a real test body, regeneration
  leaves that file alone.
- `GENERATED_HEADER` is load-bearing outside this crate:
  `crates/core/chio-core-types/tests/_generated_check.rs` asserts it
  verbatim on every file under `_generated/` and forbids a `// HAND EDIT`
  opt-out marker.

## Dependencies

No internal `chio-*` dependencies; every pass operates on repository files
and `serde_json` values only. `xtask` depends on this crate to drive the
wire-type and error-registry passes in-process (`xtask/src/codegen/rust.rs`);
the threat-model and threat-coverage-doc passes are invoked through this
crate's own binary instead and are not xtask-wired.

External: `typify` (pinned `=0.4.3`, the schema-to-Rust backend), `schemars`
0.8 (`RootSchema` parsing), `prettyplease` (deterministic formatting for the
wire-type pass), `syn` (parses generated tokens and the error-registry
buffer), `jsonschema` (threat-model schema validation), `serde`/`serde_json`.
The error-registry pass additionally shells out to the `rustfmt` binary on `PATH`.
