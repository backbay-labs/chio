# chio-spec-validate

JSON Schema validator for the Chio protocol. Provides both a library
(`chio_spec_validate::validate`) and a CLI binary (`chio-spec-validate`)
that compile a schema from `spec/schemas/` and check that a target
document conforms. Used by `cargo xtask validate-scenarios` to gate the
conformance scenarios under `tests/conformance/scenarios/` and by M04+
goldens that emit signed wire artifacts.

## CLI

```text
chio-spec-validate <schema.json> <document.json>
```

Exit code is 0 on success and non-zero on any failure (I/O, JSON parse,
schema compile, or schema violation). Diagnostics are printed to stderr.

## Library

```rust
use std::path::Path;
use chio_spec_validate::{validate, ValidateError};

fn check(schema: &Path, doc: &Path) -> Result<(), ValidateError> {
    validate(schema, doc)
}
```

`validate_value` is also exported for callers that already hold
`serde_json::Value` instances in memory.
