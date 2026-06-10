# chio-openapi Architecture Note

## Boundaries

- `src/parser.rs` owns OpenAPI 3.x JSON/YAML ingestion, required-field checks,
  local `$ref` resolution, and the intermediate `OpenApiSpec` model.
- `src/generator.rs` owns conversion from `OpenApiSpec` into
  `chio_core_types::ToolDefinition`, including parameter merging, input schema
  construction, output schema selection, and tool annotations.
- `src/extensions.rs` owns `x-chio-*` operation extension parsing.
- `src/policy.rs` owns default method-based policy decisions and extension
  overrides.
- `src/lib.rs` exposes the stable public API and the `tools_from_spec`
  convenience path.

## Parameter Ingest Boundary

The parser is the ingest trust boundary for operator-supplied OpenAPI specs;
downstream bridge code assumes parsed parameters are intentional. The normative
OpenAPI integration spec requires each parameter to include `name` and `in`, so
`parse_single_parameter` rejects parameters whose `in` field is absent, empty, or
not a string rather than publishing an invalid contract as a valid tool input and
routing bridged calls with a broader input surface than the author declared. An
explicitly unknown string `in` value remains compatible and maps to query,
matching the integration spec text; the rejected case is absence or non-string
shape, not an unknown string.

## Security And API Constraints

- Preserve the public structs and function signatures.
- Preserve JSON/YAML auto-detection and local-only `$ref` resolution.
- Preserve deterministic path ordering and method ordering.
- Preserve generator behavior for valid specs, including canonical tool input
  schemas and method-derived annotations.
- Fail closed at the malformed-spec boundary before generating tools or bridge
  route bindings.

## Affected Dependents

- `crates/protocol/chio-openapi-mcp-bridge` calls `OpenApiSpec::parse` before building
  route bindings and manifests, inheriting parameter validation without code changes.
- `spec/OPENAPI-INTEGRATION.md` is the normative contract for this crate and
  requires parameter `in` to be present.

## Verification Focus

Tests should cover JSON and YAML parsing parity, local `$ref` resolution,
required parameter fields, malformed `in` rejection, deterministic tool
ordering, stable generated input schemas, `x-chio-*` extension parsing, and
bridge compatibility through `chio-openapi-mcp-bridge` for valid specs.
