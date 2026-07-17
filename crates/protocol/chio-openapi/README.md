# chio-openapi

chio-openapi parses OpenAPI 3.0 and 3.1 specifications (JSON or YAML) and
converts each operation into a Chio `ToolDefinition`: an input schema built
from path, query, and body parameters, an optional output schema from the
response, and annotations (`read_only`, `destructive`, `idempotent`,
`requires_approval`) derived from the HTTP method and `x-chio-*` extension
fields.

Use it to turn an OpenAPI-described HTTP API into Chio tool definitions. This
crate produces `ToolDefinition` values only: it does not assemble or sign a
`ToolManifest`, host tools over MCP, or dispatch HTTP calls.
`chio-openapi-mcp-bridge` adds those steps; `chio-api-protect` consumes the
parser and policy types directly for request-time policy evaluation.

## Responsibilities

- Parse OpenAPI 3.0/3.1 documents (JSON or YAML, auto-detected) into an
  `OpenApiSpec`, resolving local `#/components/...` `$ref` pointers and
  failing closed on missing required fields or malformed parameters.
- Generate one `ToolDefinition` per operation: merge path- and
  operation-level parameters, build an input schema from path/query
  parameters and the request body, and select an output schema from the
  first 2xx response.
- Parse `x-chio-*` operation extensions (`ChioExtensions`) and apply the
  publish, side-effect, and approval-required overrides when generating tool
  annotations.
- Assign a default request policy per HTTP method (`DefaultPolicy`): safe
  methods are session-scoped allow, side-effecting methods are
  deny-by-default, both overridable via extensions.

## Public API

- `tools_from_spec(input: &str) -> Result<Vec<chio_core_types::ToolDefinition>>`
  - parse and generate in one call.
- `OpenApiSpec::{parse, from_value}`, and the parsed model
  `parser::{Operation, Parameter, ParameterLocation, PathItem}`.
- `GeneratorConfig`, `ManifestGenerator::{new, generate_tools}` - tool
  generation from a parsed spec.
- `ChioExtensions::from_operation`, `Sensitivity` - `x-chio-*` field
  extraction.
- `DefaultPolicy::{for_method, for_method_with_extensions, has_side_effects}`,
  `PolicyDecision` - method- and extension-driven policy.
- `OpenApiError`, `Result<T>` - the crate error type and its alias.

## Usage

```rust
// spec_text is an OpenAPI 3.0/3.1 document, JSON or YAML.
let tools = chio_openapi::tools_from_spec(spec_text)?;
```

## Testing

`cargo test -p chio-openapi`

## See also

- `chio-openapi-mcp-bridge` - wraps this crate's `ToolDefinition`s into an
  MCP-visible surface, assembles and signs the `ToolManifest`, and dispatches
  invocations through the kernel.
- `chio-api-protect` - consumes `OpenApiSpec`, `ChioExtensions`, and
  `DefaultPolicy` directly for request-time policy evaluation.
- `chio-core-types` - supplies the `ToolDefinition`/`ToolAnnotations` types
  this crate produces.
- `chio-http-core` - supplies `HttpMethod`, used for method parsing and
  default policy.
