# chio-errors Architecture

## Boundary

`chio-errors` owns the typed Chio error taxonomy and diagnostic construction
surface. It exposes canonical `Domain`, `Severity`, `Code`, `Diagnostic`, and
`ChioError` types, plus lookup access to the generated error registry and the
JSON-RPC bridge. It does not decide policy, evaluate guards, format CLI output,
or translate transport status codes. Callers should bring domain context and
message text; this crate should bind those messages to stable Chio registry
metadata when a registry entry exists.

## Module Boundaries

- `code` owns the serializable diagnostic code string wrapper.
- `domain` owns stable error-domain slugs and parsing.
- `severity` owns severity ordering and parsing.
- `diagnostic` owns the structured diagnostic and error types.
- `jsonrpc_bridge` owns conversion between registry entries and wire-side
  JSON-RPC numeric codes.
- `_generated::error_codes` is generated from `spec/errors/registry.yaml` by
  `chio-spec-codegen` and must not be edited directly.

## Registry Binding

Registry entries carry canonical URN, domain, severity, summary, help,
stability, string-code, and JSON-RPC metadata. Two binding paths exist, and the
ownership boundary between them is deliberate:

- `lookup_error_code` is a raw code-keyed registry query, useful for hovers and
  direct lookups.
- `Diagnostic::registry_spec` and `ChioError::registry_spec` are verified
  bindings: they return a registry entry only when the diagnostic's code,
  domain, and severity all match that entry. A free-form constructor can build
  a diagnostic whose code is a registered URN while its domain or severity
  disagrees with the registry; the verified binding rejects that case rather
  than attaching stable string-code, stability, or help metadata to a
  contradictory local error.

Generated lookup helpers stay simple by code alone. The non-generated
diagnostic API owns the stronger "is this diagnostic actually bound to the
registry entry it names" rule.

## Security And API Constraints

- Preserve public API compatibility for `Code::new`, `diagnostic`, `error`,
  registry lookup functions, and generated `ErrorCodeSpec` constants.
- Do not edit `_generated` files directly. Registry data changes must go through
  `spec/errors/registry.yaml` and `chio-spec-codegen`.
- Diagnostics built from registry entries must use the registry's URN, domain,
  severity, and help text without allowing callers to accidentally mismatch
  those fields.
- Unknown free-form codes must remain representable for compatibility CLI and transport
  surfaces.
- JSON-RPC bridge behavior must remain fail-closed for unmapped numeric codes.

## Affected Dependents

Direct dependents include `chio-cli`, `chio-control-plane`, and `chio-lsp`.
Downstream consumers through `chio-control-plane` include `chio-hosted-mcp`,
`chio-mcp-remote`, `chio-conformance`, `chio-mercury`, and `chio-wall`.
`chio-control-plane` reporting must use the verified `registry_spec` method so
it does not attach registry metadata to a mismatched diagnostic by raw code
alone.
