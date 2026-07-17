# chio-spec-validate architecture

## Overview

`chio-spec-validate` is a pure validation library: no async runtime, no
network I/O, no internal `chio-*` dependencies. It gates untrusted JSON
documents (capability tokens, receipts, wire artifacts, conformance
scenarios) against trusted, Chio-controlled JSON Schemas committed under
`spec/schemas/`. The `schema` argument to every entry point must be
Chio-controlled; the `doc` argument is the untrusted half and never drives
`$ref` resolution.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API (`validate`, `validate_value`, `load_json`, `ValidateError`), compile-option assembly, schema-registry-root detection, and `LocalSchemaRetriever`. |
| `src/main.rs` | CLI: parses two path arguments, calls `validate`, maps the result to stdout/stderr and a process exit code. |
| `tests/scenarios.rs` | Integration test against the real `spec/schemas/chio-wire/v1/capability/token.schema.json`; exercises both `validate` and `validate_value` with a valid token and one mutated to drop `signature`. |

## Validation flow

1. `validate` loads the schema and document from disk with `load_json`;
   `validate_value` skips this and takes both as `Value`s already.
2. `validate_value` derives a `file://` base URI from the schema path's parent
   directory (`schema_base_uri`) and, when that parent sits under a
   `spec/schemas/` root (`schema_registry_root`), installs a
   `LocalSchemaRetriever` scoped to that root.
3. `jsonschema::options().build(schema)` compiles the schema, invoking the
   retriever for every `$ref`. Compile failure, including any rejected `$ref`,
   returns `ValidateError::SchemaCompile`.
4. The compiled validator runs `is_valid` against the document; on failure,
   `iter_errors` collects every violation into one
   `ValidateError::SchemaViolation(schema_path, doc_path, messages)`.

## `$ref` resolution

`LocalSchemaRetriever::retrieve` dispatches on URI scheme:

| Scheme | Behavior |
|--------|----------|
| `https` | Resolved only when the URI starts with a registered Chio schema host (`https://chio.world/schemas/`, `https://chio-protocol.dev/schemas/`). The path is joined onto the schema root; if no file exists there, a directory walk matches the URI against every schema's `$id` instead, which is what lets an id like `.../token/v1` resolve to a file named `token.schema.json`. |
| `file` | Read directly by path. |
| `http` | Always rejected. |
| anything else | Rejected as `Unknown scheme {scheme}`. |

Every resolved file path is canonicalized and must fall under the
canonicalized schema root; a `file://` or `$id` resolution that would land
outside it is rejected rather than read.

## Invariants and failure modes

- No entry point panics on malformed input; I/O, parse, compile, and
  violation errors all return through `ValidateError`.
- `$ref` resolution never reaches the network: the workspace `jsonschema`
  dependency is built with `default-features = false` and only the
  `resolve-file` feature, so an `http://`/`https://` URI outside the two
  registered Chio hosts fails at schema-compile time rather than fetching
  anything (`http_ref_in_schema_does_not_fetch_network`,
  `unknown_scheme_in_schema_ref_is_rejected`).
- A schema-URI path segment of `..` is rejected while the local path is being
  built (`join_schema_path`); a `file://` `$ref` that canonicalizes outside
  the schema root is rejected after resolution
  (`file_ref_outside_schema_root_is_rejected`). Both fail closed rather than
  silently widening scope.
- `#![forbid(unsafe_code)]`.

## Dependencies

No internal `chio-*` crates. External: `jsonschema` (0.46, `default-features
= false`, `resolve-file` only) for schema compilation, and `serde_json` for
parsing and error formatting.
