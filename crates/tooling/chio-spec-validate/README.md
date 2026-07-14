# chio-spec-validate

JSON Schema validator for Chio protocol artifacts. Compiles a schema from
`spec/schemas/` and checks that a target document conforms, collecting every
violation instead of stopping at the first. Ships as both a library
(`chio_spec_validate`) and a CLI binary (`chio-spec-validate`).

`cargo xtask validate-scenarios` uses this crate to gate the conformance
scenarios under `tests/conformance/scenarios/` against their declared
`$schema`. `chio-spec-codegen` is the sibling tool that turns the same
`spec/schemas/` tree into generated Rust types; this crate only validates
documents, it does not generate code.

## Responsibilities

- Load and parse a JSON file from disk (`load_json`), reporting I/O and parse
  errors with the offending path attached.
- Compile a JSON Schema and validate a document against it, returning every
  violation message instead of failing on the first.
- Resolve `$ref` only within the local `spec/schemas/` tree: sibling-file
  references via a derived `file://` base URI, and absolute Chio schema-host
  URIs (`chio.world`, `chio-protocol.dev`) via a retriever that falls back to
  matching a schema's `$id` on disk when the URI does not map 1:1 to a file
  path.
- Fail closed on any `$ref` that would reach the network, escape the schema
  root after canonicalization, or use an unrecognized URI scheme.

## Public API

- `validate(schema_path: &Path, doc_path: &Path) -> Result<(), ValidateError>`
  - load both files from disk and validate.
- `validate_value(schema_path: &Path, schema: &Value, doc_path: &Path, doc: &Value) -> Result<(), ValidateError>`
  - validate in-memory `serde_json::Value`s; `schema_path` still drives
    base-URI and schema-registry-root detection.
- `load_json(path: &Path) -> Result<Value, ValidateError>`.
- `ValidateError` - `Io`, `Json`, `SchemaCompile`, `SchemaViolation` variants;
  implements `Display` and `std::error::Error`.

## Usage

```text
chio-spec-validate <schema.json> <document.json>
```

Exit code `0` on success, `1` on I/O, parse, compile, or schema-violation
failure, `2` on incorrect usage. Success prints `OK <document> -> <schema>` to
stdout; failures print to stderr.

```rust
use std::path::Path;
use chio_spec_validate::{validate, ValidateError};

fn check(schema: &Path, doc: &Path) -> Result<(), ValidateError> {
    validate(schema, doc)
}
```

## Testing

`cargo test -p chio-spec-validate`

## See also

- `chio-spec-codegen` - generates Rust types from the same `spec/schemas/`
  tree; this crate validates documents against it instead.
- `xtask` - `validate-scenarios` and the fixture-generation path both drive
  this crate.
