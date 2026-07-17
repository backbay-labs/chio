# chio-lsp

`chio-lsp` is the Chio language server. It runs a `tower-lsp` server over
stdio, classifies each opened document as `chio.yaml`, a tool/capability
manifest (`*.chio-manifest.yaml`), or a guard DSL file (`*.chio-guard.yaml`),
and serves diagnostics, completion, hover, and go-to-definition from a shared
document cache. It stops at the document boundary: it does not run the
kernel, evaluate policy, or read arbitrary project files.

## Responsibilities

- Cache opened documents keyed by URI and classify each by language id or URI
  suffix (`document`).
- Validate documents on `didOpen` / `didChange` and publish `urn:chio:error:*`
  diagnostics, one hand-rolled structural provider per language: required-key
  and shape checks over parsed YAML, not schema-file validation
  (`diagnostics`).
- Offer static, catalog-backed completion for capability scopes, guard
  identifiers, and top-level keys, for `chio.yaml` documents only; manifest
  and guard DSL documents currently return no completions (`completion`).
- Render hover help for capability scope, guard, and error-code URNs across
  all three document languages, sourced from the completion catalogs and the
  `chio-errors` registry (`hover`).
- Resolve `urn:chio:scope:*` / `urn:chio:guard:*` references to a definition
  site: a linked, path-scoped manifest file first, then the first occurrence
  in the open document (`definition`).
- Convert LSP UTF-16 column positions to UTF-8 byte offsets, and back, before
  every string slice so multibyte content cannot panic a request handler
  (`position`).

## Public API

- `ChioLanguageServer` - the `tower_lsp::LanguageServer` implementation; owns
  the document cache and the lifecycle / completion / hover / definition
  handlers.
- `ServerCapabilitiesSnapshot` - plain-data snapshot of the capabilities
  `ChioLanguageServer::capabilities()` advertises (full sync, completion,
  hover, definition).
- `DocumentCache`, `DocumentEntry`, `DocumentLanguage` - the open / replace /
  close document store and its language classification.
- `server::run_stdio()` - runs the server on stdin/stdout; called by the
  `chio-lsp` binary.
- `diagnostics::validate(language, uri, text) -> Vec<Diagnostic>`
- `completion::complete(language, text, position) -> Vec<CompletionItem>`
- `hover::hover(language, text, position) -> Option<Hover>`
- `definition::definition(language, uri, text, position) -> Option<Location>`
- `position::{utf16_to_byte_offset, byte_to_utf16_column}`

## Testing

`cargo test -p chio-lsp`

`cargo bench -p chio-lsp` runs the cold-start / steady-state diagnostic
latency benchmarks against a synthesized 1k-line `chio.yaml`.

## See also

- `chio-errors` - registry-generated `lookup_error_code`; backs hover text for
  `urn:chio:error:*` codes.
- `integrations/editors/` - VSCode and Zed extensions that spawn this binary
  as an LSP client over stdio.
