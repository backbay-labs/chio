# chio-spec-validate Architecture

## Boundaries

- `src/lib.rs` owns the public validation API, JSON loading, schema compilation, local schema reference resolution, and validation error reporting.
- `src/main.rs` is a thin CLI adapter. It parses paths, calls the library, and maps failures to process exit status.
- `tests/scenarios.rs` exercises the library against committed protocol schemas without depending on other Chio crates.

## Security And API Constraints

- The schema path is trusted Chio-controlled input under `spec/schemas`; the document is untrusted wire data.
- Validation must never fetch network resources. Chio schema hosts are local registry aliases, not ambient authority.
- `file://` references must stay inside the local schema root after canonicalization.
- Public API compatibility is preserved through `validate`, `validate_value`, `load_json`, and `ValidateError`.

## Pain Points

- The local retriever only maps the older `https://chio.world/schemas/` host even though current `chio-wire` schema IDs use `https://chio-protocol.dev/schemas/`.
- Exact canonical schema IDs such as `.../receipt/record/v1` do not map cleanly to file names like `record.schema.json` unless the local registry matches by `$id`.

## Planned Improvement

Resolve both Chio schema namespaces from the local schema tree, including exact `$id` lookups, while continuing to reject every non-Chio network URI.
